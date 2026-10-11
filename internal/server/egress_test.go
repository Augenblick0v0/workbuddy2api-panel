package server

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/session"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func serverProxyFixture(t *testing.T, proxies ...string) (*upstream.Client, *egress.Manager) {
	t.Helper()
	c := upstream.New()
	m, err := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{BaseTransport: c.HTTP.Transport.(*http.Transport), AllowedCIDRs: []string{"127.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(0, func(cfg *egress.Config) error {
		for i, target := range proxies {
			u, _ := url.Parse(target)
			host, port, _ := net.SplitHostPort(u.Host)
			p, _ := strconv.Atoi(port)
			id := "slot-" + strconv.Itoa(i+1)
			cfg.Slots[id] = egress.Slot{ID: id, Name: id, Enabled: true, Scheme: "http", Host: host, Port: p}
			cfg.Bindings[string(rune('A'+i))] = id
		}
		cfg.NextSlotSeq = uint64(len(proxies) + 1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c.ChatBaseCN = "http://upstream.invalid"
	c.InstallEgress(m)
	t.Cleanup(m.CloseIdleConnections)
	return c, m
}

func proxyChat(h *Handler) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"glm-5.2","stream":false,"messages":[{"role":"user","content":"fixture"}]}`)))
	return w
}

func TestProxyFailureClosed(t *testing.T) {
	for _, mode := range []string{"407", "cut", "body-cut", "refresh-407"} {
		t.Run(mode, func(t *testing.T) {
			var direct, calls atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1); w.Write([]byte(sseOK)) }))
			defer target.Close()
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "cut" {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				if mode == "body-cut" {
					w.Header().Set("Content-Length", "10000")
					w.WriteHeader(500)
					w.Write([]byte("partial"))
					return
				}
				w.WriteHeader(407)
			}))
			defer proxy.Close()
			c, m := serverProxyFixture(t, proxy.URL)
			c.ChatBaseCN = target.URL
			a := &auth.Auth{UID: "A", AccessToken: "fixture", RefreshToken: "fixture", ExpiresAt: time.Now().Add(time.Hour).Unix()}
			if mode == "refresh-407" {
				a.ExpiresAt = time.Now().Add(-time.Minute).Unix()
			}
			p := pool.New("")
			p.Add(a)
			p.SetRouteAvailable(m.Available)
			h := NewHandler(Config{Pool: p, Upstream: c, MaxRotate: 4})
			w := proxyChat(h)
			code := "proxy_auth_failed"
			if mode == "cut" || mode == "body-cut" {
				code = "upstream_transport_failed"
			}
			if !strings.Contains(w.Body.String(), `"code":"`+code+`"`) {
				t.Fatalf("unstable error %d %s", w.Code, w.Body.String())
			}
			st, _ := p.Status("A")
			if calls.Load() != 1 || direct.Load() != 0 || st.ErrTotal != 0 || st.ConsecutiveFails != 0 || st.Disabled || st.InFlight != 0 || st.Cooling {
				t.Fatalf("leak/replay/punishment calls=%d direct=%d state=%+v", calls.Load(), direct.Load(), st)
			}
		})
	}
}

func TestProxyWAFIsolation(t *testing.T) {
	for _, sameIP := range []bool{false, true} {
		t.Run(strconv.FormatBool(sameIP), func(t *testing.T) {
			var calls atomic.Int64
			makeProxy := func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.WriteHeader(403)
					w.Write([]byte("<html>blocked</html>"))
				}))
			}
			a, b := makeProxy(), makeProxy()
			defer a.Close()
			defer b.Close()
			c, m := serverProxyFixture(t, a.URL, b.URL)
			c.ChatBaseCN = "http://upstream.invalid"
			snapshot := m.Snapshot()
			_, err := m.Update(snapshot.Revision, func(cfg *egress.Config) error {
				for i, id := range []string{"slot-1", "slot-2"} {
					ip := "203.0.113." + strconv.Itoa(i+1)
					if sameIP {
						ip = "203.0.113.1"
					}
					cfg.ProbeResults[id] = egress.ProbeResult{SlotID: id, Generation: cfg.Slots[id].TransportGeneration, IP: ip, Status: "ok", CheckedAt: time.Now()}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			p := pool.New("")
			p.Add(&auth.Auth{UID: "A", AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour).Unix()})
			p.SetRouteAvailable(m.Available)
			h := NewHandler(Config{Pool: p, Upstream: c, MaxRotate: 1})
			proxyChat(h)
			p.Add(&auth.Auth{UID: "B", AccessToken: "b", ExpiresAt: time.Now().Add(time.Hour).Unix()})
			second := proxyChat(h)
			if calls.Load() != 2 {
				t.Fatalf("unexpected attempts %d", calls.Load())
			}
			if sameIP {
				if !strings.Contains(second.Body.String(), "proxy_waf_blocked") || second.Header().Get("Retry-After") == "" {
					t.Fatalf("same-IP bucket not blocked: %s", second.Body.String())
				}
				third := proxyChat(h)
				if calls.Load() != 2 || !strings.Contains(third.Body.String(), "proxy_waf_blocked") {
					t.Fatal("WAF window leaked outbound")
				}
			} else {
				if strings.Contains(second.Body.String(), "proxy_waf_blocked") || !m.Available("A") || !m.Available("B") {
					t.Fatal("different IP buckets contaminated")
				}
			}
		})
	}
}

func TestProxyStickyBlockedStopsBeforeReplacement(t *testing.T) {
	var calls atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(sseOK)) }))
	defer proxy.Close()
	c, m := serverProxyFixture(t, proxy.URL)
	p := pool.New("")
	p.Add(&auth.Auth{UID: "A", AccessToken: "a"})
	p.Add(&auth.Auth{UID: "ready", AccessToken: "b"})
	p.SetRouteAvailable(m.Available)
	router := session.New(session.Config{Available: p.AvailableUIDs, AvailableForModel: p.AvailableUIDsForModel})
	router.Bind("fixture", "A")
	_, err := m.Update(m.Snapshot().Revision, func(cfg *egress.Config) error {
		s := cfg.Slots["slot-1"]
		s.Enabled = false
		cfg.Slots[s.ID] = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(Config{Pool: p, Upstream: c, Session: router})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"glm-5.2","metadata":{"conversationId":"fixture"},"messages":[{"role":"user","content":"fixture"}]}`)))
	if !strings.Contains(w.Body.String(), "proxy_unavailable") || calls.Load() != 0 {
		t.Fatalf("sticky replaced blocked route: %d %s", calls.Load(), w.Body.String())
	}
	if _, ok := router.Peek("fixture"); ok {
		t.Fatal("blocked sticky not unbound")
	}
}
