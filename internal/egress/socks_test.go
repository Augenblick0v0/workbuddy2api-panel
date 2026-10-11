package egress_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

type socksSeen struct {
	host, username, password string
	port                     int
}

// A real local SOCKS5 handshake and tunnel, not a mocked RoundTripper.
type socksFixture struct {
	listener  net.Listener
	target    string
	mode      string
	seen      chan socksSeen
	started   chan struct{}
	closed    chan struct{}
	once      sync.Once
	closeOnce sync.Once
	conns     sync.Map
	wg        sync.WaitGroup
}

func newSocksFixture(t *testing.T, target, mode string) *socksFixture {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksFixture{listener: l, target: target, mode: mode, seen: make(chan socksSeen, 20), started: make(chan struct{}), closed: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			s.conns.Store(c, true)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				defer s.conns.Delete(c)
				defer s.closeOnce.Do(func() { close(s.closed) })
				s.serve(c)
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		s.conns.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		s.wg.Wait()
	})
	return s
}

func (s *socksFixture) serve(c net.Conn) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var h [4]byte
	if _, err := io.ReadFull(c, h[:2]); err != nil {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	s.once.Do(func() { close(s.started) })
	switch s.mode {
	case "stall":
		c.SetDeadline(time.Time{})
		io.Copy(io.Discard, c) // client cancellation must close its socket
		return
	case "malformed":
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	case "reject-method":
		c.Write([]byte{5, 255})
		return
	}
	var seen socksSeen
	if s.mode == "auth" || s.mode == "bad-auth" {
		c.Write([]byte{5, 2})
		if _, err := io.ReadFull(c, h[:2]); err != nil {
			return
		}
		u := make([]byte, int(h[1]))
		if _, err := io.ReadFull(c, u); err != nil {
			return
		}
		if _, err := io.ReadFull(c, h[:1]); err != nil {
			return
		}
		p := make([]byte, int(h[0]))
		if _, err := io.ReadFull(c, p); err != nil {
			return
		}
		seen.username, seen.password = string(u), string(p)
		if s.mode == "bad-auth" {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	} else {
		c.Write([]byte{5, 0})
	}
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	if h[0] != 5 || h[1] != 1 || h[2] != 0 {
		return
	}
	switch h[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		seen.host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		seen.host = net.IP(b).String()
	case 3:
		if _, err := io.ReadFull(c, h[:1]); err != nil {
			return
		}
		b := make([]byte, int(h[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		seen.host = string(b)
	default:
		return
	}
	if _, err := io.ReadFull(c, h[:2]); err != nil {
		return
	}
	seen.port = int(binary.BigEndian.Uint16(h[:2]))
	s.seen <- seen
	if s.mode == "reject-connect" {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	dst, err := net.DialTimeout("tcp", s.target, time.Second)
	if err != nil {
		return
	}
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
	c.SetDeadline(time.Time{})
	copyTunnel(dst, c, c)
}

func TestSOCKSRemoteDNSAndCredentials(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		for _, auth := range []bool{false, true} {
			t.Run(scheme+map[bool]string{false: "-anonymous", true: "-auth"}[auth], func(t *testing.T) {
				var calls atomic.Int64
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "Bearer synthetic-account" {
						t.Error("credential separation failed")
					}
					w.Write([]byte("via-socks"))
				}))
				defer target.Close()
				mode := ""
				if auth {
					mode = "auth"
				}
				f := newSocksFixture(t, target.Listener.Addr().String(), mode)
				slot := slotFor(t, scheme+"://"+f.listener.Addr().String())
				if auth {
					slot.Username, slot.Password = "fixture:@用户", "p@ss/?#"
				}
				m := managerWithSlot(t, slot, egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
				h, err := m.ResolveAccount("account")
				if err != nil {
					t.Fatal(err)
				}
				defer h.Release()
				req, _ := http.NewRequestWithContext(egress.WithRoute(context.Background(), h), "GET", "http://only-at-proxy.invalid:3210/", nil)
				req.Header.Set("Authorization", "Bearer synthetic-account")
				req.Header.Set("Proxy-Authorization", "must-be-stripped")
				res, err := (&http.Client{Transport: m}).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(res.Body)
				res.Body.Close()
				seen := <-f.seen
				if string(b) != "via-socks" || calls.Load() != 1 || seen.host != "only-at-proxy.invalid" || seen.port != 3210 ||
					seen.username != slot.Username || seen.password != slot.Password {
					t.Fatal("SOCKS handshake or remote DNS mismatch")
				}
			})
		}
	}
}

func TestSOCKSHTTPSAndFailureClosed(t *testing.T) {
	var upstream atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		w.Write([]byte(`{"ip":"203.0.113.11"}`))
	}))
	defer target.Close()
	f := newSocksFixture(t, target.Listener.Addr().String(), "")
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{RootCAs: roots}
	m := managerWithSlot(t, slotFor(t, "socks5://"+f.listener.Addr().String()), egress.Options{
		BaseTransport: base, AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: target.URL,
	})
	result, err := m.Probe(context.Background(), "slot-1")
	if err != nil || result.IP != "203.0.113.11" {
		t.Fatal(result, err)
	}
	m.CloseIdleConnections()
	f.listener.Close()
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	_, err = send(t, m, h, target.URL)
	var ee *egress.EgressError
	if !errors.As(err, &ee) || ee.Code != "proxy_connect_failed" || m.Available("account") || upstream.Load() != 1 {
		t.Fatalf("disconnected proxy fell through: err=%v requests=%d", err, upstream.Load())
	}
}

func TestSOCKSRecoversAfterTransientFailureWithoutProbe(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			var calls, directDials atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				io.WriteString(w, "recovered-via-socks")
			}))
			defer target.Close()
			f := newSocksFixture(t, target.Listener.Addr().String(), "")
			var fault atomic.Bool
			fault.Store(true)
			base := http.DefaultTransport.(*http.Transport).Clone()
			dial := &net.Dialer{}
			base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == target.Listener.Addr().String() {
					directDials.Add(1)
				}
				if fault.Load() {
					return nil, errors.New("synthetic transient proxy dial failure")
				}
				return dial.DialContext(ctx, network, address)
			}
			m := managerWithSlot(t, slotFor(t, scheme+"://"+f.listener.Addr().String()), egress.Options{
				BaseTransport: base, AllowedCIDRs: []string{"127.0.0.0/8"}, FailureCooldown: 200 * time.Millisecond,
			})
			h, err := m.ResolveAccount("account")
			if err != nil {
				t.Fatal(err)
			}
			defer h.Release()
			if _, err = send(t, m, h, target.URL); err == nil || m.Available("account") || calls.Load() != 0 {
				t.Fatal("SOCKS fault did not stop the operation", err)
			}
			fault.Store(false)
			deadline := time.Now().Add(2 * time.Second)
			for !m.Available("account") && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			next, err := m.ResolveAccount("account")
			if err != nil {
				t.Fatal("SOCKS recovery still needs manual exit detection", err)
			}
			defer next.Release()
			resp, err := send(t, m, next, target.URL)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(raw) != "recovered-via-socks" || calls.Load() != 1 || directDials.Load() != 0 ||
				next.SlotID != h.SlotID || next.Generation != h.Generation {
				t.Fatalf("wrong SOCKS recovery: body=%q calls=%d direct=%d", raw, calls.Load(), directDials.Load())
			}
		})
	}
}

func TestSOCKSHandshakeErrors(t *testing.T) {
	for _, tc := range []struct{ mode, code string }{
		{"bad-auth", "proxy_auth_failed"}, {"reject-method", "proxy_auth_failed"},
		{"downgrade", "proxy_auth_failed"},
		{"malformed", "proxy_connect_failed"}, {"reject-connect", "proxy_connect_failed"},
		{"stall", "proxy_timeout"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			var direct atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1) }))
			defer target.Close()
			f := newSocksFixture(t, target.Listener.Addr().String(), tc.mode)
			slot := slotFor(t, "socks5://"+f.listener.Addr().String())
			if tc.mode == "bad-auth" || tc.mode == "reject-method" || tc.mode == "downgrade" {
				slot.Username, slot.Password = "synthetic-user", "synthetic-secret"
			}
			m := managerWithSlot(t, slot, egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
			h, err := m.ResolveAccount("account")
			if err != nil {
				t.Fatal(err)
			}
			defer h.Release()
			ctx, cancel := context.WithTimeout(egress.WithRoute(context.Background(), h), 300*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
			_, err = (&http.Client{Transport: m}).Do(req)
			var ee *egress.EgressError
			if !errors.As(err, &ee) || ee.Code != tc.code || direct.Load() != 0 {
				t.Fatalf("mode=%s error=%v direct=%d", tc.mode, err, direct.Load())
			}
			raw, _ := json.Marshal(ee)
			if strings.Contains(string(raw), "synthetic-") {
				t.Fatal("secret in error")
			}
		})
	}
}

func TestSOCKSCredentialsAndPrivateEndpointValidation(t *testing.T) {
	for _, invalid := range []egress.Slot{
		{Username: strings.Repeat("a", 256)}, {Username: "u", Password: strings.Repeat("p", 256)}, {Password: "password-only"},
	} {
		m, err := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{})
		if err != nil {
			t.Fatal(err)
		}
		invalid.ID, invalid.Scheme, invalid.Host, invalid.Port, invalid.Enabled = "slot-1", "socks5", "127.0.0.1", 1080, true
		if _, err = m.Update(0, func(c *egress.Config) error { c.NextSlotSeq = 2; c.Slots[invalid.ID] = invalid; return nil }); err == nil {
			t.Fatal("invalid SOCKS credentials accepted")
		}
	}
	f := newSocksFixture(t, "", "")
	m := managerWithSlot(t, slotFor(t, "socks5://"+f.listener.Addr().String()), egress.Options{})
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	if _, err = send(t, m, h, "http://not-resolved.invalid/"); err == nil {
		t.Fatal("private proxy permitted without allowlist")
	}
	select {
	case <-f.started:
		t.Fatal("prohibited endpoint contacted")
	default:
	}
}

func TestSOCKSConfigSurvivesRestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "proxies.json")
	m, err := egress.Open(file, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(0, func(c *egress.Config) error {
		c.NextSlotSeq = 2
		c.Slots["slot-1"] = egress.Slot{ID: "slot-1", Scheme: "socks5h", Host: "proxy.invalid", Port: 1080, Username: "u", Password: "p", Enabled: true}
		c.Bindings["account"] = "slot-1"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := egress.Open(file, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := reopened.Snapshot()
	if c.Slots["slot-1"].Scheme != "socks5h" || c.Slots["slot-1"].Password != "p" || c.Bindings["account"] != "slot-1" {
		t.Fatal("SOCKS config lost on restart")
	}
}

func TestSOCKSCancellationDoesNotPenalizeProxy(t *testing.T) {
	f := newSocksFixture(t, "", "stall")
	m := managerWithSlot(t, slotFor(t, "socks5://"+f.listener.Addr().String()), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	ctx, cancel := context.WithCancel(egress.WithRoute(context.Background(), h))
	defer cancel()
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://only-at-proxy.invalid/", nil)
		_, err := (&http.Client{Transport: m}).Do(req)
		done <- err
	}()
	<-f.started
	cancel()
	select {
	case err := <-done:
		if err == nil || !m.Available("account") {
			t.Fatal("caller cancellation penalized proxy", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled SOCKS handshake hung")
	}
	select {
	case <-f.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled SOCKS handshake leaked an open socket")
	}
}

func TestSOCKSGenerationKeepsEstablishedStream(t *testing.T) {
	release := make(chan struct{})
	oldTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("old-"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("complete"))
	}))
	defer oldTarget.Close()
	newTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("new")) }))
	defer newTarget.Close()
	oldProxy := newSocksFixture(t, oldTarget.Listener.Addr().String(), "")
	newProxy := newSocksFixture(t, newTarget.Listener.Addr().String(), "")
	m := managerWithSlot(t, slotFor(t, "socks5://"+oldProxy.listener.Addr().String()), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	old, err := send(t, m, h, "http://stream-at-proxy.invalid/")
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer old.Body.Close()
	first := make([]byte, 4)
	io.ReadFull(old.Body, first)
	snap := m.Snapshot()
	_, err = m.Update(snap.Revision, func(c *egress.Config) error {
		c.Slots["slot-1"] = slotFor(t, "socks5h://"+newProxy.listener.Addr().String())
		return nil
	})
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	next, err := m.ResolveAccount("account")
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer next.Release()
	res, err := send(t, m, next, "http://stream-at-proxy.invalid/")
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	tail, err := io.ReadAll(old.Body)
	if err != nil || string(first)+string(tail) != "old-complete" || string(b) != "new" || next.Generation != h.Generation+1 {
		t.Fatal("SOCKS generation interrupted stream", err)
	}
	if res, err := send(t, m, h, "http://stream-at-proxy.invalid/"); err == nil {
		res.Body.Close()
		t.Fatal("retired SOCKS generation accepted request")
	}
}
