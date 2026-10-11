package panel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// A proxy can reject the public probe while accepting the actual billing host.
// Exercise the public management and balance APIs, not a mocked route decision.
func TestProxyProbeFailureDoesNotBlockBalance(t *testing.T) {
	var billingCalls, directDials atomic.Int64
	var broken atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-balance-token" {
			t.Error("billing request lost the synthetic account credential")
		}
		billingCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code":0,"data":{"limitNum":1000,"credit":250}}`)
	}))
	defer target.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if r.Method != http.MethodConnect {
			if r.Header.Get("Authorization") != "" {
				t.Error("probe leaked an account credential")
			}
			io.WriteString(w, `{"ip":"203.0.113.9"}`)
			return
		}
		if r.Host != target.Listener.Addr().String() {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		dst, err := net.Dial("tcp", target.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			dst.Close()
			t.Error(err)
			return
		}
		buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		buffered.Flush()
		go func() {
			defer dst.Close()
			defer client.Close()
			done := make(chan struct{})
			go func() { io.Copy(dst, buffered); dst.Close(); close(done) }()
			io.Copy(client, dst)
			client.Close()
			<-done
		}()
	}))
	defer proxy.Close()
	c := upstream.New()
	c.BillingBaseGlobal = target.URL
	base := c.HTTP.Transport.(*http.Transport)
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	base.TLSClientConfig = &tls.Config{RootCAs: roots}
	dial := base.DialContext
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == target.Listener.Addr().String() {
			directDials.Add(1)
		}
		return dial(ctx, network, address)
	}
	m, err := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{
		BaseTransport: base, AllowedCIDRs: []string{"127.0.0.0/8"},
		ProbeURL: "http://probe.invalid/ip", ProbeHTTPSURL: "https://probe.invalid/ip",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.CloseIdleConnections)
	u, _ := url.Parse(proxy.URL)
	port, _ := strconv.Atoi(u.Port())
	_, err = m.Update(0, func(cfg *egress.Config) error {
		cfg.NextSlotSeq = 2
		cfg.Slots["slot-1"] = egress.Slot{ID: "slot-1", Name: "fixture", Enabled: true, Scheme: "http", Host: u.Hostname(), Port: port}
		cfg.Bindings["u1"] = "slot-1"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c.InstallEgress(m)
	pl := pool.New("")
	pl.SetRouteAvailable(m.Available)
	a, err := auth.Parse([]byte(`{"uid":"u1","realm":"global","enterpriseId":"synthetic-enterprise","accessToken":"synthetic-balance-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	pl.Add(a)
	p := New(Config{Pool: pl, Upstream: c, Egress: m, APIKey: "key"})
	probe := proxyCall(t, p, "POST", "/panel/api/proxies/slot-1/test", `{"generation":1}`, "")
	if probe.Code != 200 || !strings.Contains(probe.Body.String(), `"proxy_status":400`) {
		t.Fatalf("expected diagnostic CONNECT 400: %d %s", probe.Code, probe.Body)
	}
	balance := proxyCall(t, p, "POST", "/panel/api/accounts/u1/balance", `{}`, "")
	if balance.Code != 200 || !strings.Contains(balance.Body.String(), `"credits":750`) {
		t.Fatalf("probe failure blocked the real balance request: %d %s", balance.Code, balance.Body)
	}
	if billingCalls.Load() != 1 || directDials.Load() != 0 || !m.Available("u1") {
		t.Fatalf("wrong routing after probe: billing=%d direct=%d available=%t", billingCalls.Load(), directDials.Load(), m.Available("u1"))
	}

	// An actual proxy failure still stops the request and subsequent sends.
	broken.Store(true)
	m.CloseIdleConnections()
	failed := proxyCall(t, p, "POST", "/panel/api/accounts/u1/balance", `{}`, "")
	if failed.Code != 502 || !strings.Contains(failed.Body.String(), "proxy_auth_failed") || m.Available("u1") {
		t.Fatalf("actual proxy fault was ignored: %d %s", failed.Code, failed.Body)
	}
	proxyCall(t, p, "POST", "/panel/api/proxies/slot-1/test", `{}`, "")
	blocked := proxyCall(t, p, "POST", "/panel/api/accounts/u1/balance", `{}`, "")
	if blocked.Code != 502 || !strings.Contains(blocked.Body.String(), "proxy_unavailable") ||
		billingCalls.Load() != 1 || directDials.Load() != 0 {
		t.Fatalf("failed probe cleared a business fault or leaked direct: %d %s billing=%d direct=%d",
			blocked.Code, blocked.Body, billingCalls.Load(), directDials.Load())
	}
}
