package server

import (
	"bytes"
	"context"
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
	m, err := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{BaseTransport: c.HTTP.Transport.(*http.Transport), AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.invalid/ip", ProbeMode: "legacy"})
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

func TestProxyWAFThresholdSurvivesProbePublication(t *testing.T) {
	var chats, probes atomic.Int64
	makeProxy := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ip" {
				probes.Add(1)
				w.Write([]byte(`{"ip":"203.0.113.8"}`))
				return
			}
			chats.Add(1)
			w.WriteHeader(403)
			w.Write([]byte("<html>blocked</html>"))
		}))
	}
	first, second := makeProxy(), makeProxy()
	defer first.Close()
	defer second.Close()
	c, m := serverProxyFixture(t, first.URL, second.URL)
	p := pool.New("")
	p.Add(&auth.Auth{UID: "A", AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	p.SetRouteAvailable(m.Available)
	h := NewHandler(Config{Pool: p, Upstream: c, MaxRotate: 1})
	proxyChat(h) // UID A records a pre-probe unknown-slot hit.
	for _, id := range []string{"slot-1", "slot-2"} {
		if _, err := m.Probe(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	p.Add(&auth.Auth{UID: "B", AccessToken: "b", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	w := proxyChat(h) // UID B's now-known IP must merge A's original hit.
	if !strings.Contains(w.Body.String(), "proxy_waf_blocked") || m.Available("A") || m.Available("B") {
		t.Fatalf("probe reset WAF threshold: %s", w.Body.String())
	}
	proxyChat(h)
	if chats.Load() != 2 || probes.Load() != 2 {
		t.Fatalf("WAF/probe counts chats=%d probes=%d", chats.Load(), probes.Load())
	}
}

func TestProxyWAFAliasMergeKeepsLatestHitAndLongestWindow(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ip":"203.0.113.8"}`)) }))
	defer proxy.Close()
	_, m := serverProxyFixture(t, proxy.URL, proxy.URL)
	now := time.Now()
	longest := now.Add(2 * time.Minute)
	g := routeWAFGates{buckets: map[string]*wafIPGate{
		"slot-1:1": {hits: map[string]time.Time{"same": now.Add(-time.Second)}, until: now.Add(time.Minute)},
		"slot-2:1": {hits: map[string]time.Time{"same": now, "other": now}, until: longest},
	}}
	for _, id := range []string{"slot-1", "slot-2"} {
		if _, err := m.Probe(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	until, blocked := g.note(m, "slot-1:1", "same")
	b := g.buckets["ip:203.0.113.8"]
	if !blocked || !until.Equal(longest) || b == nil || !b.hits["same"].Equal(now) || len(b.hits) != 2 || len(g.buckets) != 1 {
		t.Fatalf("alias merge lost hits/window: until=%v blocked=%v buckets=%+v", until, blocked, g.buckets)
	}
}

func TestProxyStaleRefreshSessionDeadDoesNotDisableReplacement(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	var chats atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/auth/token/refresh") {
			close(entered)
			<-resume
			w.WriteHeader(401)
			w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
			return
		}
		chats.Add(1)
		if r.Header.Get("Authorization") != "Bearer new-login" {
			t.Error("chat used stale token")
		}
		w.Write([]byte(sseOK))
	}))
	defer server.Close()
	a := &auth.Auth{UID: "A", AccessToken: "old", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(-time.Minute).Unix(), FilePath: filepath.Join(t.TempDir(), "auth.json")}
	c := upstream.New()
	c.ChatBaseCN = server.URL
	p := pool.New("")
	p.Add(a)
	h := NewHandler(Config{Pool: p, Upstream: c, MaxRotate: 1})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- proxyChat(h) }()
	<-entered
	if err := a.ReplaceCredentials(&auth.Auth{UID: "A", AccessToken: "new-login", RefreshToken: "new-refresh", ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	p.Revive("A")
	close(resume)
	w := <-done
	state, _ := p.Status("A")
	if w.Code != 200 || state.Disabled || state.ErrTotal != 0 || state.InFlight != 0 || chats.Load() != 1 || a.AccessTokenValue() != "new-login" {
		t.Fatalf("stale refresh punished fresh credentials: %d %s %+v chats=%d", w.Code, w.Body.String(), state, chats.Load())
	}
}
