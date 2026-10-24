package egress_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func copyTunnel(dst, client net.Conn, buffered io.Reader) {
	defer dst.Close()
	defer client.Close()
	done := make(chan struct{})
	go func() { io.Copy(dst, buffered); dst.Close(); close(done) }()
	io.Copy(client, dst)
	client.Close()
	<-done
}

func TestProbeHTTPIPDoesNotHideConnectFailure(t *testing.T) {
	var httpCalls, connects atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("account credentials in probe")
		}
		if r.Method == http.MethodConnect {
			connects.Add(1)
			w.WriteHeader(400)
			return
		}
		httpCalls.Add(1)
		w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{
		AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeMode: "legacy", ProbeURL: "http://ip.invalid/",
		ProbeHTTPSURL: "https://tls.invalid/",
	})
	result, err := m.Probe(context.Background(), "slot-1")
	if err == nil || result.Status != "error" || result.IP != "203.0.113.9" ||
		result.IPStatus != "ok" || result.HTTPSStatus != "error" ||
		result.ProxyStatus != 400 || result.ErrorStage != "connect" ||
		result.ErrorReason != "connect_rejected" || !result.SuccessfulAt.IsZero() {
		t.Fatalf("HTTP success hid HTTPS failure: %+v err=%v", result, err)
	}
	if httpCalls.Load() != 1 || connects.Load() != 1 || !m.Available("account") {
		t.Fatalf("unexpected requests/availability: http=%d connect=%d available=%t",
			httpCalls.Load(), connects.Load(), m.Available("account"))
	}
}

func TestProbeTransportFailuresAreAdvisory(t *testing.T) {
	for _, mode := range []string{"http_auth", "target_status", "proxy_dial", "socks_auth", "socks_timeout", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "http_auth" {
					w.WriteHeader(http.StatusProxyAuthRequired)
				} else {
					w.WriteHeader(http.StatusBadGateway)
				}
			}))
			defer proxy.Close()
			slot := slotFor(t, proxy.URL)
			if mode == "proxy_dial" {
				proxy.Close()
			}
			if mode == "socks_auth" || mode == "socks_timeout" {
				fault := "bad-auth"
				if mode == "socks_timeout" {
					fault = "stall"
				}
				socks := newSocksFixture(t, "", fault)
				slot = slotFor(t, "socks5://"+socks.listener.Addr().String())
				slot.Username, slot.Password = "synthetic-user", "synthetic-password"
			}
			m := managerWithSlot(t, slot, egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.invalid/"})
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			result, err := m.Probe(ctx, "slot-1")
			if err == nil || result.Status != "error" {
				t.Fatalf("failed probe was reported as success: result=%+v err=%v", result, err)
			}
			if !m.Available("account") {
				t.Fatalf("diagnostic failure blocked business route: mode=%s status=%+v", mode, m.Status("account"))
			}
		})
	}
}

func TestProbeHTTPSCanSucceedWhenHTTPFails(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.10"}`))
	}))
	defer target.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(503)
			return
		}
		dst, err := net.Dial("tcp", target.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			dst.Close()
			return
		}
		rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		rw.Flush()
		go copyTunnel(dst, client, rw)
	}))
	defer proxy.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{RootCAs: roots}
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{
		BaseTransport: base, AllowedCIDRs: []string{"127.0.0.0/8"},
		ProbeMode: "legacy", ProbeURL: "http://ip.invalid/", ProbeHTTPSURL: target.URL,
	})
	result, err := m.Probe(context.Background(), "slot-1")
	if err != nil || result.Status != "ok" || result.HTTPSStatus != "ok" ||
		result.IP != "203.0.113.10" || result.SuccessfulAt.IsZero() || !m.Available("account") {
		t.Fatalf("HTTPS did not independently verify route: %+v err=%v", result, err)
	}
}

func TestHTTPOnlyObservationDoesNotMoveWAFToAnotherExit(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(`{"ip":"203.0.113.20"}`))
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{
		AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeMode: "legacy", ProbeURL: "http://ip.invalid/", ProbeHTTPSURL: "https://tls.invalid/",
	})
	_, err := m.Update(m.Snapshot().Revision, func(c *egress.Config) error {
		s := c.Slots["slot-1"]
		s.ID = "slot-2"
		c.Slots["slot-2"] = s
		c.NextSlotSeq = 3
		c.Bindings["other"] = "slot-2"
		c.ProbeResults["slot-1"] = egress.ProbeResult{SlotID: "slot-1", Generation: 1, IP: "203.0.113.10", Status: "ok"}
		c.ProbeResults["slot-2"] = egress.ProbeResult{SlotID: "slot-2", Generation: 1, IP: "203.0.113.20", Status: "ok"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m.BlockWAF("ip:203.0.113.10", time.Now().Add(time.Minute))
	result, err := m.Probe(context.Background(), "slot-1")
	if err == nil || result.IP != "203.0.113.20" || result.VerifiedIP != "203.0.113.10" {
		t.Fatal("lost display or trusted route evidence", result, err)
	}
	if m.Status("other").State != "ready" || m.Status("account").State != "waf_blocked" ||
		m.Status("account").RouteKey != "ip:203.0.113.10" {
		t.Fatal("plaintext observation contaminated another WAF exit")
	}
}
