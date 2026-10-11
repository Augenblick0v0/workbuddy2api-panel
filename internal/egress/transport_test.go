package egress_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
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

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func slotFor(t *testing.T, raw string) egress.Slot {
	t.Helper()
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	p, e := strconv.Atoi(u.Port())
	if e != nil {
		t.Fatal(e)
	}
	return egress.Slot{ID: "slot-1", Name: "fixture", Enabled: true, Scheme: u.Scheme, Host: u.Hostname(), Port: p}
}
func managerWithSlot(t *testing.T, s egress.Slot, opts egress.Options) *egress.Manager {
	t.Helper()
	m, e := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), opts)
	if e != nil {
		t.Fatal(e)
	}
	_, e = m.Update(0, func(c *egress.Config) error {
		c.NextSlotSeq = 2
		c.Slots[s.ID] = s
		c.Bindings["account"] = s.ID
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(m.CloseIdleConnections)
	return m
}
func send(t *testing.T, m *egress.Manager, h *egress.RouteHandle, raw string) (*http.Response, error) {
	t.Helper()
	req, e := http.NewRequestWithContext(egress.WithRoute(context.Background(), h), http.MethodGet, raw, nil)
	if e != nil {
		t.Fatal(e)
	}
	return (&http.Client{Transport: m}).Do(req)
}
func TestEgressFailureClosed(t *testing.T) {
	var direct atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1); w.Write([]byte("target")) }))
	defer target.Close()
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1); w.Write([]byte("proxy")) }))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
	req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	if _, e := m.RoundTrip(req); e == nil {
		t.Fatal("missing route context sent")
	}
	h, e := m.ResolveAccount("account")
	if e != nil {
		t.Fatal(e)
	}
	resp, e := send(t, m, h, target.URL)
	h.Release()
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "proxy" || proxied.Load() != 1 || direct.Load() != 0 {
		t.Fatal("proxy route leaked direct")
	}
	s := m.Snapshot()
	_, e = m.Update(s.Revision, func(c *egress.Config) error { x := c.Slots["slot-1"]; x.Enabled = false; c.Slots[x.ID] = x; return nil })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.ResolveAccount("account"); e == nil {
		t.Fatal("disabled bound route allowed")
	}
	if m.Available("account") || m.Status("account").State != "disabled" {
		t.Fatal("availability wrong")
	}
	if direct.Load() != 0 {
		t.Fatal("direct contacted")
	}
}
func TestEgressPrivateRequiresExplicitAllow(t *testing.T) {
	var calls atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{})
	h, e := m.ResolveAccount("account")
	if e != nil {
		t.Fatal(e)
	}
	defer h.Release()
	if _, e = send(t, m, h, "http://upstream.invalid/"); e == nil {
		t.Fatal("private proxy permitted")
	}
	if calls.Load() != 0 {
		t.Fatal("private proxy contacted")
	}
}

func TestEgressConnect(t *testing.T) {
	const username = "fixture:u@name"
	const password = "fixture p@ss/%"
	var upstreamCalls atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials leaked upstream")
		}
		if r.Header.Get("Authorization") != "Bearer account-fixture" {
			t.Error("upstream authorization lost")
		}
		w.Write([]byte("upstream"))
	}))
	defer target.Close()
	var connects atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("expected CONNECT, got %s", r.Method)
			w.WriteHeader(500)
			return
		}
		connects.Add(1)
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		if r.Header.Get("Proxy-Authorization") != want {
			t.Errorf("bad proxy auth")
			w.WriteHeader(407)
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("account auth leaked to CONNECT")
		}
		dst, e := net.Dial("tcp", r.Host)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		client, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			dst.Close()
			return
		}
		rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		rw.Flush()
		go func() { io.Copy(dst, rw); dst.Close() }()
		go func() { io.Copy(client, dst); client.Close() }()
	})
	for _, secure := range []bool{false, true} {
		t.Run(strconv.FormatBool(secure), func(t *testing.T) {
			var proxy *httptest.Server
			if secure {
				proxy = httptest.NewTLSServer(handler)
			} else {
				proxy = httptest.NewServer(handler)
			}
			defer proxy.Close()
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			if secure {
				roots.AddCert(proxy.Certificate())
			}
			base := http.DefaultTransport.(*http.Transport).Clone()
			base.TLSClientConfig = &tls.Config{RootCAs: roots}
			slot := slotFor(t, proxy.URL)
			slot.Username = username
			slot.Password = password
			m := managerWithSlot(t, slot, egress.Options{BaseTransport: base, AllowedCIDRs: []string{"127.0.0.0/8"}})
			h, e := m.ResolveAccount("account")
			if e != nil {
				t.Fatal(e)
			}
			defer h.Release()
			req, _ := http.NewRequestWithContext(egress.WithRoute(context.Background(), h), http.MethodGet, target.URL, nil)
			req.Header.Set("Authorization", "Bearer account-fixture")
			req.Header.Set("Proxy-Authorization", "attacker-injected")
			resp, e := (&http.Client{Transport: m}).Do(req)
			if e != nil {
				t.Fatal(e)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != "upstream" {
				t.Fatal("wrong response")
			}
		})
	}
	if connects.Load() != 2 || upstreamCalls.Load() != 2 {
		t.Fatalf("CONNECT=%d upstream=%d", connects.Load(), upstreamCalls.Load())
	}
}
func TestEgressProxyCertificatesAnd407(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(strconv.FormatBool(secure), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(407) })
			var proxy *httptest.Server
			if secure {
				proxy = httptest.NewTLSServer(handler)
			} else {
				proxy = httptest.NewServer(handler)
			}
			defer proxy.Close()
			m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
			h, e := m.ResolveAccount("account")
			if e != nil {
				t.Fatal(e)
			}
			defer h.Release()
			_, e = send(t, m, h, "http://upstream.invalid/")
			var ee *egress.EgressError
			if !errors.As(e, &ee) {
				t.Fatalf("not typed: %v", e)
			}
			want := "proxy_auth_failed"
			if secure {
				want = "proxy_connect_failed"
			}
			if ee.Code != want {
				t.Fatalf("got %s want %s", ee.Code, want)
			}
			if m.Available("account") {
				t.Fatal("failed proxy still available")
			}
		})
	}
}
func TestEgressGenerationBarrier(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("old-"))
		w.(http.Flusher).Flush()
		close(started)
		<-release
		w.Write([]byte("complete"))
	}))
	defer old.Close()
	newProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("new")) }))
	defer newProxy.Close()
	m := managerWithSlot(t, slotFor(t, old.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
	h, e := m.ResolveAccount("account")
	if e != nil {
		t.Fatal(e)
	}
	resp, e := send(t, m, h, "http://upstream.invalid")
	if e != nil {
		t.Fatal(e)
	}
	<-started
	s := m.Snapshot()
	_, e = m.Update(s.Revision, func(c *egress.Config) error { n := slotFor(t, newProxy.URL); c.Slots[n.ID] = n; return nil })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = send(t, m, h, "http://upstream.invalid"); e == nil {
		t.Fatal("stale handle accepted new request")
	}
	h.Release()
	newHandle, e := m.ResolveAccount("account")
	if e != nil {
		t.Fatal(e)
	}
	next, e := send(t, m, newHandle, "http://upstream.invalid")
	newHandle.Release()
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(next.Body)
	next.Body.Close()
	if string(b) != "new" {
		t.Fatal("new request wrong generation")
	}
	close(release)
	b, e = io.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil || string(b) != "old-complete" {
		t.Fatalf("old stream interrupted: %q %v", b, e)
	}
}

type fixtureResolver struct{ calls atomic.Int64 }

func (r *fixtureResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if r.calls.Add(1) == 1 {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}, nil
	}
	return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
}
func TestEgressDNSRebindingAndMetadata(t *testing.T) {
	var contacted atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacted.Add(1); w.Write([]byte("proxy")) }))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	resolver := &fixtureResolver{}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DisableKeepAlives = true
	var dials atomic.Int64
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		if !strings.HasPrefix(addr, "203.0.113.9:") {
			t.Errorf("dial was not validated pinned IP: %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, proxyURL.Host)
	}
	slot := slotFor(t, proxy.URL)
	slot.Host = "rebind.invalid"
	m := managerWithSlot(t, slot, egress.Options{BaseTransport: base, Resolver: resolver, AllowedCIDRs: []string{"0.0.0.0/0"}})
	h, e := m.ResolveAccount("account")
	if e != nil {
		t.Fatal(e)
	}
	defer h.Release()
	resp, e := send(t, m, h, "http://upstream.invalid/")
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if _, e = send(t, m, h, "http://upstream.invalid/"); e == nil {
		t.Fatal("rebound metadata IP accepted")
	}
	if dials.Load() != 1 || contacted.Load() != 1 {
		t.Fatal("metadata reached socket")
	}
	for _, ip := range []string{"169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "fe80::1"} {
		t.Run(ip, func(t *testing.T) {
			s := slot
			s.Host = ip
			var called atomic.Int64
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
				called.Add(1)
				return nil, errors.New("dial should be blocked")
			}
			mm := managerWithSlot(t, s, egress.Options{BaseTransport: tr, AllowedCIDRs: []string{"0.0.0.0/0", "::/0"}})
			hh, err := mm.ResolveAccount("account")
			if err != nil {
				t.Fatal(err)
			}
			defer hh.Release()
			if _, err = send(t, mm, hh, "http://upstream.invalid"); err == nil {
				t.Fatal("metadata allowed")
			}
			if called.Load() != 0 {
				t.Fatal("metadata dial invoked")
			}
		})
	}
}
func TestEgressExplicitDirectIgnoresEnvironment(t *testing.T) {
	var proxyCalls atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("direct carried proxy authorization")
		}
		w.Write([]byte("direct"))
	}))
	defer target.Close()
	m, e := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer m.CloseIdleConnections()
	h, e := m.ResolveSlot("")
	if e != nil {
		t.Fatal(e)
	}
	defer h.Release()
	req, _ := http.NewRequestWithContext(egress.WithRoute(context.Background(), h), http.MethodGet, target.URL, nil)
	req.Header.Set("Proxy-Authorization", "secret")
	res, e := (&http.Client{Transport: m}).Do(req)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != "direct" || proxyCalls.Load() != 0 {
		t.Fatal("direct honored ambient proxy")
	}
}
