package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func isolationManager(t *testing.T, isolated bool) *Manager {
	t.Helper()
	m, err := Open(filepath.Join(t.TempDir(), "proxies.json"), Options{
		IsolateAccountConnections: isolated,
		AllowedCIDRs:              []string{"127.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.CloseIdleConnections)
	return m
}

func isolationSlot(t *testing.T, raw string) Slot {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return Slot{ID: "slot-1", Enabled: true, Scheme: u.Scheme, Host: u.Hostname(), Port: port}
}

func isolationUpdate(t *testing.T, m *Manager, edit func(*Config)) {
	t.Helper()
	_, err := m.Update(m.Snapshot().Revision, func(c *Config) error { edit(c); return nil })
	if err != nil {
		t.Fatal(err)
	}
}

func isolationSend(m *Manager, h *RouteHandle, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(WithRoute(context.Background(), h), http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return (&http.Client{Transport: m}).Do(req)
}

func isolationRead(t *testing.T, m *Manager, h *RouteHandle, target string) string {
	t.Helper()
	res, err := isolationSend(m, h, target)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func isolationAccount(t *testing.T, m *Manager, uid string) *RouteHandle {
	t.Helper()
	h, err := m.ResolveAccount(uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Release)
	return h
}

func TestAccountConnectionIsolationAndReuse(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		for _, proxied := range []bool{false, true} {
			t.Run(fmt.Sprintf("isolated=%t/proxy=%t", isolated, proxied), func(t *testing.T) {
				endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, r.RemoteAddr)
				}))
				defer endpoint.Close()
				m := isolationManager(t, isolated)
				target := endpoint.URL
				if proxied {
					isolationUpdate(t, m, func(c *Config) {
						c.NextSlotSeq = 2
						c.Slots["slot-1"] = isolationSlot(t, endpoint.URL)
						c.Bindings["a"], c.Bindings["b"] = "slot-1", "slot-1"
					})
					target = "http://upstream.invalid/"
				}
				a1, b := isolationAccount(t, m, "a"), isolationAccount(t, m, "b")
				first := isolationRead(t, m, a1, target)
				a1.Release()
				// A newly resolved handle must reuse its own pool after the
				// first RPC body closes; SSE uses the identical manager path.
				a2 := isolationAccount(t, m, "a")
				if again := isolationRead(t, m, a2, target); again != first {
					t.Fatal("same account did not reuse connection")
				}
				other := isolationRead(t, m, b, target)
				if isolated && other == first {
					t.Fatal("different accounts shared a connection")
				}
				if !isolated && other != first {
					t.Fatal("legacy slot-level reuse changed")
				}
				slotID := ""
				if proxied {
					slotID = "slot-1"
				}
				preidentity, err := m.ResolveSlot(slotID)
				if err != nil {
					t.Fatal(err)
				}
				defer preidentity.Release()
				oauth := isolationRead(t, m, preidentity, target)
				if isolated && oauth == first {
					t.Fatal("pre-identity pool shared account connection")
				}
				if a2.RouteKey != b.RouteKey || preidentity.RouteKey != a2.RouteKey {
					t.Fatal("connection isolation changed logical exit identity")
				}
			})
		}
	}
}

func TestAccountIsolationSharedWAFAndProxyFailureClosed(t *testing.T) {
	var direct atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
		io.WriteString(w, "direct")
	}))
	defer target.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	m := isolationManager(t, true)
	isolationUpdate(t, m, func(c *Config) {
		c.NextSlotSeq = 2
		c.Slots["slot-1"] = isolationSlot(t, proxy.URL)
		c.Bindings["a"], c.Bindings["b"] = "slot-1", "slot-1"
	})
	a, b := isolationAccount(t, m, "a"), isolationAccount(t, m, "b")
	if a.transportKey == b.transportKey || a.RouteKey != b.RouteKey {
		t.Fatal("account pools or shared route identity wrong")
	}
	m.BlockWAF(a.RouteKey, time.Now().Add(time.Minute))
	if m.Status("a").State != "waf_blocked" || m.Status("b").State != "waf_blocked" {
		t.Fatal("account pool isolation split shared WAF protection")
	}
	// Clear only the fixture's block to check transport failure independently.
	m.mu.Lock()
	m.waf = map[string]time.Time{}
	m.publishRuntimeLocked()
	m.mu.Unlock()
	_, err := isolationSend(m, a, target.URL)
	var ee *EgressError
	if !errors.As(err, &ee) || ee.Code != "proxy_auth_failed" {
		t.Fatalf("expected typed proxy failure, got %v", err)
	}
	if m.Status("b").State != "unavailable" {
		t.Fatal("shared broken proxy was not paused for second account")
	}
	if _, err = isolationSend(m, b, target.URL); err == nil {
		t.Fatal("second account sent through failed proxy")
	}
	if direct.Load() != 0 {
		t.Fatalf("proxy failure leaked %d direct requests", direct.Load())
	}
}

func TestAccountIsolationRetireRebindAndPreserveBody(t *testing.T) {
	release := make(chan struct{})
	released := false
	original := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			io.WriteString(w, "direct")
			return
		}
		io.WriteString(w, "old-")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "complete")
	}))
	defer original.Close()
	defer func() {
		if !released {
			close(release)
		}
	}()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "proxy")
	}))
	defer proxy.Close()
	m := isolationManager(t, true)
	isolationUpdate(t, m, func(c *Config) {
		c.NextSlotSeq = 2
		c.Slots["slot-1"] = isolationSlot(t, proxy.URL)
		c.Bindings["a"] = ""
	})
	old := isolationAccount(t, m, "a")
	res, err := isolationSend(m, old, original.URL+"/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	isolationUpdate(t, m, func(c *Config) { c.Bindings["a"] = "slot-1" })
	if _, err = isolationSend(m, old, original.URL); err == nil {
		t.Fatal("stale bound handle accepted a new send")
	}
	old.Release()
	if g := m.transports[old.transportKey]; g == nil || !g.retired {
		t.Fatal("referenced response body lost retired transport ownership")
	}
	next := isolationAccount(t, m, "a")
	if got := isolationRead(t, m, next, original.URL); got != "proxy" {
		t.Fatalf("rebound account used wrong exit: %q", got)
	}
	next.Release()
	isolationUpdate(t, m, func(c *Config) { c.Bindings["a"] = "" })
	back := isolationAccount(t, m, "a")
	if back.transportKey == old.transportKey {
		t.Fatal("route-away-and-back reused retired pool ownership")
	}
	if got := isolationRead(t, m, back, original.URL); got != "direct" {
		t.Fatalf("explicit direct route not restored: %q", got)
	}
	close(release)
	released = true
	data, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(data) != "old-complete" {
		t.Fatalf("old response stream interrupted: %q %v", data, err)
	}
	if m.transports[old.transportKey] != nil || m.transports[next.transportKey] != nil {
		t.Fatal("retired account pool retained after final owner release")
	}
	back.Release()
	isolationUpdate(t, m, func(c *Config) { delete(c.Bindings, "a") })
	if m.transports[back.transportKey] != nil || m.accountPools["a"] != "" {
		t.Fatal("unbound idle account pool was not removed")
	}
}

func TestAccountIsolationCacheBoundAndPendingGuard(t *testing.T) {
	m := isolationManager(t, true)
	for i := 0; i < maxCachedAccountPools+32; i++ {
		h := isolationAccount(t, m, fmt.Sprintf("account-%d", i))
		h.Release()
	}
	if len(m.accountPools) > maxCachedAccountPools || len(m.transports) > maxCachedAccountPools {
		t.Fatalf("historical account pools accumulated: accounts=%d transports=%d", len(m.accountPools), len(m.transports))
	}
	h := isolationAccount(t, m, "pending")
	isolationUpdate(t, m, func(c *Config) { c.PendingAccounts["pending"] = true })
	if _, err := m.ResolveAccount("pending"); err == nil {
		t.Fatal("pending credentials obtained isolated account route")
	}
	_, err := isolationSend(m, h, "http://upstream.invalid")
	var ee *EgressError
	if !errors.As(err, &ee) || ee.Code != "proxy_account_transition" {
		t.Fatalf("old isolated handle bypassed pending guard: %v", err)
	}
}

func TestAccountIsolationGenerationAndDeleteGuard(t *testing.T) {
	m := isolationManager(t, true)
	isolationUpdate(t, m, func(c *Config) {
		c.NextSlotSeq = 2
		c.Slots["slot-1"] = Slot{ID: "slot-1", Enabled: true, Scheme: "http", Host: "127.0.0.1", Port: 12345}
		c.Bindings["a"] = "slot-1"
	})
	old := isolationAccount(t, m, "a")
	if !m.InUse("slot-1") {
		t.Fatal("isolated account handle missing from slot ownership")
	}
	isolationUpdate(t, m, func(c *Config) {
		s := c.Slots["slot-1"]
		s.Port++
		c.Slots[s.ID] = s
	})
	next := isolationAccount(t, m, "a")
	if next.Generation != old.Generation+1 || next.transportKey == old.transportKey {
		t.Fatal("network edit did not replace account pool generation")
	}
	if g := m.transports[old.transportKey]; g == nil || !g.retired {
		t.Fatal("old generation retired before its caller released")
	}
	if err := m.CheckCurrent(old); err == nil {
		t.Fatal("old generation passed current-route check")
	}
	_, err := m.Update(m.Snapshot().Revision, func(c *Config) error {
		delete(c.Bindings, "a")
		delete(c.Slots, "slot-1")
		return nil
	})
	var ee *EgressError
	if !errors.As(err, &ee) || ee.Code != "proxy_in_use" {
		t.Fatalf("slot delete bypassed isolated caller guard: %v", err)
	}
	old.Release()
	next.Release()
	isolationUpdate(t, m, func(c *Config) {
		delete(c.Bindings, "a")
		delete(c.Slots, "slot-1")
	})
	if len(m.accountPools) != 0 || len(m.transports) != 0 {
		t.Fatal("deleted slot left isolated transports cached")
	}
}

func TestAccountIsolationLegacyPinnedRouteRetryCompatibility(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		t.Run(strconv.FormatBool(isolated), func(t *testing.T) {
			var firstCalls, secondCalls atomic.Int64
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				firstCalls.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, "confirmed server error")
			}))
			defer first.Close()
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				secondCalls.Add(1)
				io.WriteString(w, "new route")
			}))
			defer second.Close()
			m := isolationManager(t, isolated)
			isolationUpdate(t, m, func(c *Config) {
				c.NextSlotSeq = 3
				c.Slots["slot-1"] = isolationSlot(t, first.URL)
				s := isolationSlot(t, second.URL)
				s.ID = "slot-2"
				c.Slots[s.ID] = s
				c.Bindings["a"] = "slot-1"
			})
			pinned := isolationAccount(t, m, "a")
			if got := isolationRead(t, m, pinned, "http://upstream.invalid/"); got != "confirmed server error" {
				t.Fatalf("unexpected baseline server response: %q", got)
			}
			isolationUpdate(t, m, func(c *Config) { c.Bindings["a"] = "slot-2" })
			res, err := isolationSend(m, pinned, "http://upstream.invalid/")
			if isolated {
				if err == nil {
					res.Body.Close()
					t.Fatal("isolated retired binding accepted a new send")
				}
			} else {
				if err != nil {
					t.Fatalf("legacy pinned server-error retry blocked: %v", err)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode != http.StatusInternalServerError {
					t.Fatal("legacy pinned retry moved to new route")
				}
			}
			wantOld := int64(2)
			if isolated {
				wantOld = 1
			}
			if firstCalls.Load() != wantOld || secondCalls.Load() != 0 {
				t.Fatalf("pinned retry route changed: old=%d new=%d", firstCalls.Load(), secondCalls.Load())
			}
			current := isolationAccount(t, m, "a")
			if got := isolationRead(t, m, current, "http://upstream.invalid/"); got != "new route" {
				t.Fatalf("new account operation used stale route: %q", got)
			}
			if secondCalls.Load() != 1 {
				t.Fatal("new operation did not use current binding exactly once")
			}
		})
	}
}
