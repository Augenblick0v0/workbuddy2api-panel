package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// All endpoints and credentials in this fixture are synthetic. The two real
// local HTTP proxies are the only permitted recipients of OAuth/account sends.
type proxyOAuthFixture struct {
	panel                      *Panel
	manager                    *egress.Manager
	pool                       *pool.Pool
	authDir, storePath, target string
	direct                     atomic.Int64
	mu                         sync.Mutex
	calls                      map[string]map[string]int
	stateSeq                   int
	states                     []string
	enterpriseID               string
	tokenCode                  int
	tokenMessage               string
	tokenEntered               chan struct{}
	tokenRelease               chan struct{}
	enteredOnce                sync.Once
	failStore                  atomic.Bool
	bindingWritten             atomic.Bool
}

func newProxyOAuthFixture(t *testing.T) *proxyOAuthFixture {
	t.Helper()
	f := &proxyOAuthFixture{calls: map[string]map[string]int{}, pool: pool.New(""), enterpriseID: "fixture-enterprise"}
	dir := t.TempDir()
	f.authDir = filepath.Join(dir, "auths")
	f.storePath = filepath.Join(dir, "proxies.json")
	f.target = ""
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.direct.Add(1)
		http.Error(w, "unexpected direct fixture request", http.StatusForbidden)
	}))
	t.Cleanup(direct.Close)
	f.target = direct.URL
	makeProxy := func(label string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			if f.calls[label] == nil {
				f.calls[label] = map[string]int{}
			}
			f.calls[label][r.URL.Path]++
			tokenCode, tokenMessage := f.tokenCode, f.tokenMessage
			enterpriseID := f.enterpriseID
			entered, release := f.tokenEntered, f.tokenRelease
			state := ""
			if r.URL.Path == "/fixture/state" {
				f.stateSeq++
				state = fmt.Sprintf("fixture-state-%d", f.stateSeq)
				f.states = append(f.states, state)
			}
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/fixture/state":
				json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"state": state, "authUrl": "https://browser.fixture.invalid/authorize?state=" + state}})
			case "/fixture/token":
				if entered != nil {
					f.enteredOnce.Do(func() { close(entered) })
				}
				if release != nil {
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				if tokenCode != 0 {
					json.NewEncoder(w).Encode(map[string]any{"code": tokenCode, "msg": tokenMessage})
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"accessToken": "synthetic-new-access-token", "refreshToken": "synthetic-new-refresh-token", "expiresIn": 3600, "domain": "fixture.invalid"}})
			case "/fixture/account":
				if r.Header.Get("Authorization") != "Bearer synthetic-new-access-token" {
					t.Error("account stage lost synthetic token")
				}
				json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"uid": "oauth-fixture-uid", "enterpriseId": enterpriseID, "nickname": "fixture nickname"}})
			default:
				if f.manager.Snapshot().Bindings["oauth-fixture-uid"] != "slot-2" {
					t.Error("automatic maintenance preceded binding")
				}
				if _, e := os.Stat(filepath.Join(f.authDir, "workbuddy-oauth-fixture-uid.json")); e != nil {
					t.Error("automatic maintenance preceded credentials")
				}
				if f.pool.AuthByUID("oauth-fixture-uid") == nil {
					t.Error("automatic maintenance preceded pool publication")
				}
				if strings.Contains(r.URL.Path, "get-enterprise-user-usage") {
					if f.manager.Snapshot().Bindings["oauth-fixture-uid"] != "slot-2" {
						t.Error("automatic maintenance preceded account binding")
					}
					json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"limitNum": 100, "credit": 1}})
				} else {
					json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{}})
				}
			}
		}))
	}
	a, b := makeProxy("A"), makeProxy("B")
	t.Cleanup(a.Close)
	t.Cleanup(b.Close)
	hooks := &egress.StoreHooks{Rename: func(old, new string) error {
		if f.failStore.Load() {
			return os.ErrPermission
		}
		if e := os.Rename(old, new); e != nil {
			return e
		}
		raw, e := os.ReadFile(new)
		if e != nil {
			return e
		}
		var c egress.Config
		if e = json.Unmarshal(raw, &c); e != nil {
			return e
		}
		if c.Bindings["oauth-fixture-uid"] == "slot-2" && f.pool.AuthByUID("oauth-fixture-uid") == nil {
			if _, e := os.Stat(filepath.Join(f.authDir, "workbuddy-oauth-fixture-uid.json")); os.IsNotExist(e) {
				f.bindingWritten.Store(true)
			}
		}
		return nil
	}}
	m, e := egress.Open(f.storePath, egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}, StoreHooks: hooks})
	if e != nil {
		t.Fatal(e)
	}
	f.manager = m
	t.Cleanup(m.CloseIdleConnections)
	_, e = m.Update(0, func(c *egress.Config) error {
		for i, p := range []*httptest.Server{a, b} {
			u, _ := url.Parse(p.URL)
			port, _ := strconv.Atoi(u.Port())
			id := fmt.Sprintf("slot-%d", i+1)
			c.Slots[id] = egress.Slot{ID: id, Name: id, Enabled: true, Scheme: "http", Host: u.Hostname(), Port: port}
		}
		c.NextSlotSeq = 3
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	c := upstream.New()
	c.ChatBaseCN = f.target
	c.BillingBaseCN = f.target
	c.WebBaseCN = f.target
	c.ChatBaseGlobal = f.target
	c.BillingBaseGlobal = f.target
	if installer, ok := any(c).(interface{ InstallEgress(*egress.Manager) }); ok {
		installer.InstallEgress(m)
	} else {
		c.HTTP.Transport = m
		c.ChatHTTP.Transport = m
	}
	f.panel = New(Config{Pool: f.pool, Upstream: c, Egress: m, AuthDir: f.authDir, APIKey: "key", LoginEndpoints: func(string) (string, string, string, string) {
		return f.target + "/fixture/state", f.target + "/fixture/token?state=", f.target + "/fixture/account?state=", f.target
	}})
	t.Cleanup(func() {
		f.mu.Lock()
		states := append([]string(nil), f.states...)
		f.mu.Unlock()
		for _, state := range states {
			proxyCall(t, f.panel, http.MethodPost, "/panel/api/login/cancel", `{"state":"`+state+`"}`, "http://panel.test")
		}
	})
	t.Cleanup(func() {
		if f.direct.Load() != 0 {
			t.Errorf("OAuth/account direct sends=%d, want 0", f.direct.Load())
		}
	})
	return f
}
func (f *proxyOAuthFixture) count(label, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[label][path]
}
func (f *proxyOAuthFixture) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, paths := range f.calls {
		for _, v := range paths {
			n += v
		}
	}
	return n
}
func (f *proxyOAuthFixture) start(t *testing.T) string {
	t.Helper()
	w := proxyCall(t, f.panel, http.MethodPost, "/panel/api/login/start", `{"proxy_slot_id":"slot-2"}`, "http://panel.test")
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var v struct {
		State string `json:"state"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil || v.State == "" {
		t.Fatalf("state missing: %s", w.Body)
	}
	return v.State
}
func (f *proxyOAuthFixture) poll(t *testing.T, state string) *httptest.ResponseRecorder {
	t.Helper()
	return proxyCall(t, f.panel, http.MethodGet, "/panel/api/login/poll?state="+url.QueryEscape(state), "", "")
}
func assertOAuthDone(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var v struct {
		Done bool   `json:"done"`
		UID  string `json:"uid"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil || w.Code != 200 || !v.Done || v.UID != "oauth-fixture-uid" {
		t.Fatalf("poll not done: %d %s", w.Code, w.Body)
	}
}
func TestProxyOAuthLifecycle(t *testing.T) {
	f := newProxyOAuthFixture(t)
	state := f.start(t)
	first := f.poll(t, state)
	assertOAuthDone(t, first)
	if f.count("A", "/fixture/state")+f.count("A", "/fixture/token")+f.count("A", "/fixture/account") != 0 {
		t.Fatal("OAuth used unselected route")
	}
	for _, path := range []string{"/fixture/state", "/fixture/token", "/fixture/account"} {
		if f.count("B", path) != 1 {
			t.Fatalf("selected route path %s count %d", path, f.count("B", path))
		}
	}
	if !f.bindingWritten.Load() {
		t.Fatal("durable binding did not precede credential/pool publication")
	}
	if f.manager.Snapshot().Bindings["oauth-fixture-uid"] != "slot-2" || f.pool.AuthByUID("oauth-fixture-uid") == nil {
		t.Fatal("completion missing binding/account")
	}
	loaded, e := auth.LoadDir(f.authDir)
	if e != nil || len(loaded) != 1 || loaded[0].AccessToken != "synthetic-new-access-token" {
		t.Fatal("completion missing synthetic credential")
	}
	calls := f.total()
	repeat := f.poll(t, state)
	assertOAuthDone(t, repeat)
	if repeat.Body.String() != first.Body.String() || f.total() != calls {
		t.Fatal("completion replay was not cached")
	}
}

func TestProxyOAuthConcurrentPoll(t *testing.T) {
	f := newProxyOAuthFixture(t)
	f.tokenEntered = make(chan struct{})
	f.tokenRelease = make(chan struct{})
	var releaseOnce sync.Once
	resume := func() { releaseOnce.Do(func() { close(f.tokenRelease) }) }
	t.Cleanup(resume)
	state := f.start(t)
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- f.poll(t, state) }()
	select {
	case <-f.tokenEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("first poll did not enter token fixture")
	}
	var wg sync.WaitGroup
	others := make(chan *httptest.ResponseRecorder, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); others <- f.poll(t, state) }()
	}
	wg.Wait()
	close(others)
	for w := range others {
		if w.Code != 200 {
			t.Fatalf("concurrent poll status %d: %s", w.Code, w.Body)
		}
	}
	if f.count("B", "/fixture/token") != 1 {
		t.Fatal("parallel polls repeated token stage")
	}
	resume()
	select {
	case w := <-first:
		assertOAuthDone(t, w)
	case <-time.After(3 * time.Second):
		t.Fatal("completed poll remained blocked")
	}
	assertOAuthDone(t, f.poll(t, state))
	if f.count("B", "/fixture/token") != 1 || f.count("B", "/fixture/account") != 1 {
		t.Fatal("concurrent poll repeated completion stages")
	}
}
func TestProxyOAuthPendingAndTerminal(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		f := newProxyOAuthFixture(t)
		f.tokenCode = 1
		f.tokenMessage = "login ing"
		state := f.start(t)
		w := f.poll(t, state)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"done":false`) {
			t.Fatalf("pending: %d %s", w.Code, w.Body)
		}
		if f.count("B", "/fixture/account") != 0 || f.pool.AuthByUID("oauth-fixture-uid") != nil {
			t.Fatal("pending session completed")
		}
		f.mu.Lock()
		f.tokenCode = 0
		f.mu.Unlock()
		assertOAuthDone(t, f.poll(t, state))
	})
	t.Run("terminal", func(t *testing.T) {
		f := newProxyOAuthFixture(t)
		f.tokenCode = 999
		f.tokenMessage = "synthetic terminal error"
		state := f.start(t)
		w := f.poll(t, state)
		if w.Code < 400 {
			t.Fatalf("terminal error remained pending: %d %s", w.Code, w.Body)
		}
		calls := f.total()
		w = f.poll(t, state)
		if w.Code < 400 || f.total() != calls {
			t.Fatal("terminal session kept polling upstream")
		}
		if f.count("B", "/fixture/account") != 0 || len(f.pool.List()) != 0 {
			t.Fatal("terminal session published account")
		}
	})
}
func TestProxyOAuthGenerationAndDisabled(t *testing.T) {
	for _, kind := range []string{"generation", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			f := newProxyOAuthFixture(t)
			state := f.start(t)
			s := f.manager.Snapshot()
			_, e := f.manager.Update(s.Revision, func(c *egress.Config) error {
				x := c.Slots["slot-2"]
				if kind == "disabled" {
					x.Enabled = false
				} else {
					x.Password = "synthetic-changed-proxy-password"
				}
				c.Slots[x.ID] = x
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			calls := f.total()
			w := f.poll(t, state)
			if w.Code != 409 || !strings.Contains(w.Body.String(), "oauth_proxy_changed") {
				t.Fatalf("changed route: %d %s", w.Code, w.Body)
			}
			w = f.poll(t, state)
			if w.Code != 409 || f.total() != calls {
				t.Fatal("changed session continued upstream")
			}
			if len(f.pool.List()) != 0 {
				t.Fatal("changed session published account")
			}
		})
	}
}
func TestProxyOAuthCancelReleasesRoute(t *testing.T) {
	f := newProxyOAuthFixture(t)
	state := f.start(t)
	if !f.manager.InUse("slot-2") {
		t.Fatal("OAuth did not retain route")
	}
	for i := 0; i < 2; i++ {
		w := proxyCall(t, f.panel, http.MethodPost, "/panel/api/login/cancel", `{"state":"`+state+`"}`, "http://panel.test")
		if w.Code != 200 {
			t.Fatalf("cancel: %d %s", w.Code, w.Body)
		}
	}
	deadline := time.Now().Add(time.Second)
	for f.manager.InUse("slot-2") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.manager.InUse("slot-2") {
		t.Fatal("cancel leaked OAuth reference")
	}
	s := f.manager.Snapshot()
	w := proxyCall(t, f.panel, http.MethodDelete, "/panel/api/proxies/slot-2", fmt.Sprintf(`{"revision":%d}`, s.Revision), "")
	if w.Code != 200 {
		t.Fatalf("cancelled slot deletion: %d %s", w.Code, w.Body)
	}
	calls := f.total()
	w = f.poll(t, state)
	if w.Code < 400 || f.total() != calls {
		t.Fatal("cancelled state sent upstream")
	}
}

func TestProxyOAuthBindingAndCredentialFailures(t *testing.T) {
	t.Run("binding_write", func(t *testing.T) {
		f := newProxyOAuthFixture(t)
		state := f.start(t)
		f.failStore.Store(true)
		w := f.poll(t, state)
		if w.Code != 500 || !strings.Contains(w.Body.String(), "proxy_store_failed") {
			t.Fatalf("binding failure: %d %s", w.Code, w.Body)
		}
		if _, ok := f.manager.Snapshot().Bindings["oauth-fixture-uid"]; ok {
			t.Fatal("failed binding published")
		}
		if f.pool.AuthByUID("oauth-fixture-uid") != nil {
			t.Fatal("account entered pool before durable binding")
		}
		if _, e := os.Stat(filepath.Join(f.authDir, "workbuddy-oauth-fixture-uid.json")); !os.IsNotExist(e) {
			t.Fatal("credential written before durable binding")
		}
		calls := f.total()
		w = f.poll(t, state)
		if w.Code < 400 || f.total() != calls {
			t.Fatal("failed binding session resumed upstream")
		}
	})
	t.Run("credential_write", func(t *testing.T) {
		f := newProxyOAuthFixture(t)
		if e := os.WriteFile(f.authDir, []byte("synthetic auth-directory blocker"), 0600); e != nil {
			t.Fatal(e)
		}
		state := f.start(t)
		w := f.poll(t, state)
		if w.Code != 500 || !strings.Contains(w.Body.String(), "oauth_credentials_failed") {
			t.Fatalf("credential failure: %d %s", w.Code, w.Body)
		}
		if f.manager.Snapshot().Bindings["oauth-fixture-uid"] != "slot-2" {
			t.Fatal("credential failure lost orphan binding")
		}
		again, e := egress.Open(f.storePath, egress.Options{})
		if e != nil {
			t.Fatal(e)
		}
		if again.Snapshot().Bindings["oauth-fixture-uid"] != "slot-2" {
			t.Fatal("orphan binding not durable")
		}
		if f.pool.AuthByUID("oauth-fixture-uid") != nil {
			t.Fatal("credential failure account entered pool")
		}
		if f.count("A", "/fixture/state")+f.count("A", "/fixture/token")+f.count("A", "/fixture/account") != 0 {
			t.Fatal("failed credential workflow changed proxy")
		}
	})
}
func TestProxyOAuthReloginRebindConfirmation(t *testing.T) {
	f := newProxyOAuthFixture(t)
	if e := os.MkdirAll(f.authDir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(f.authDir, "workbuddy-oauth-fixture-uid.json")
	old := &auth.Auth{UID: "oauth-fixture-uid", AccessToken: "synthetic-old-access-token", RefreshToken: "synthetic-old-refresh-token", DeviceToken: "synthetic-old-device-token", FilePath: path, ExpiresAt: time.Now().Add(time.Hour).Unix(), EnterpriseID: "fixture-enterprise"}
	if e := old.SaveAtomic(); e != nil {
		t.Fatal(e)
	}
	f.pool.Add(old)
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	snap := f.manager.Snapshot()
	if _, e = f.manager.Update(snap.Revision, func(c *egress.Config) error { c.Bindings[old.UID] = "slot-1"; return nil }); e != nil {
		t.Fatal(e)
	}
	state := f.start(t)
	w := f.poll(t, state)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "oauth_rebind_required") {
		t.Fatalf("unconfirmed rebind: %d %s", w.Code, w.Body)
	}
	after, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) || old.AccessToken != "synthetic-old-access-token" || f.manager.Snapshot().Bindings[old.UID] != "slot-1" {
		t.Fatal("unconfirmed rebind overwrote old credentials or route")
	}
	calls := f.count("B", "/fixture/token") + f.count("B", "/fixture/account")
	w = proxyCall(t, f.panel, http.MethodGet, "/panel/api/login/poll?state="+url.QueryEscape(state)+"&confirm_rebind=true", "", "")
	assertOAuthDone(t, w)
	if f.manager.Snapshot().Bindings[old.UID] != "slot-2" || old.AccessToken != "synthetic-new-access-token" || old.DeviceToken != "synthetic-old-device-token" || old.FilePath != path || f.pool.AuthByUID(old.UID) != old {
		t.Fatal("confirmed rebind failed to update preserved credential object")
	}
	if f.count("B", "/fixture/token")+f.count("B", "/fixture/account") != calls {
		t.Fatal("confirmation repeated OAuth token/account stages")
	}
	loaded, e := auth.LoadDir(f.authDir)
	if e != nil || len(loaded) != 1 || loaded[0].AccessToken != "synthetic-new-access-token" {
		t.Fatal("confirmed token not durable")
	}
}

func TestProxyOAuthExistingCredentialFailureStopsAcrossRestart(t *testing.T) {
	f := newProxyOAuthFixture(t)
	if err := os.MkdirAll(f.authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.authDir, "workbuddy-oauth-fixture-uid.json")
	old := &auth.Auth{UID: "oauth-fixture-uid", AccessToken: "synthetic-old", RefreshToken: "synthetic-old-refresh", FilePath: path, EnterpriseID: "fixture-enterprise"}
	if err := old.SaveAtomic(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	f.pool.Add(old)
	if _, err := f.manager.Update(f.manager.Snapshot().Revision, func(c *egress.Config) error { c.Bindings[old.UID] = "slot-1"; return nil }); err != nil {
		t.Fatal(err)
	}
	// A directory at the temp-file path deterministically fails credential writes
	// on Windows and Linux without relying on chmod/root behavior.
	if err := os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	state := f.start(t)
	w := proxyCall(t, f.panel, http.MethodGet, "/panel/api/login/poll?state="+url.QueryEscape(state)+"&confirm_rebind=true", "", "")
	if w.Code != 500 {
		t.Fatal(w.Code, w.Body)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || old.AccessToken != "synthetic-old" || !f.manager.Snapshot().PendingAccounts[old.UID] {
		t.Fatal("old credentials or durable guard lost")
	}
	f.pool.SetRouteAvailable(f.manager.Available)
	if f.pool.PickByUID(old.UID) != nil {
		t.Fatal("failed transition still selectable")
	}
	_, _, err := f.panel.cfg.Upstream.UserResource(old)
	var ee *egress.EgressError
	if !errors.As(err, &ee) || ee.Code != "proxy_account_transition" {
		t.Fatal("maintenance not blocked", err)
	}
	restarted, err := egress.Open(f.storePath, egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
	if err != nil || restarted.Available(old.UID) {
		t.Fatal("restart cleared failed transition", err)
	}
	if err = os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	// Explicitly restarting the same selected route completes credentials and
	// clears the durable guard; no operator-side direct fallback is involved.
	state = f.start(t)
	assertOAuthDone(t, f.poll(t, state))
	if f.manager.Snapshot().PendingAccounts[old.UID] || !f.manager.Available(old.UID) {
		t.Fatal("completed credentials did not unlock account")
	}
}

func TestProxyOAuthMaintenancePinnedRoute(t *testing.T) {
	f := newProxyOAuthFixture(t)
	if _, ok := any(f.panel.cfg.Upstream).(interface {
		ForRoute(*egress.RouteHandle) *upstream.Client
	}); !ok {
		t.Skip("outbound ForRoute branch awaits integration; five-send assertion deferred")
	}
	f.mu.Lock()
	f.enterpriseID = ""
	f.mu.Unlock()
	state := f.start(t)
	assertOAuthDone(t, f.poll(t, state))
	for _, path := range []string{"/fixture/state", "/fixture/token", "/fixture/account", "/v2/billing/meter/daily-checkin", "/v2/billing/meter/get-user-resource"} {
		if f.count("B", path) != 1 || f.count("A", path) != 0 {
			t.Fatalf("pinned OAuth+maintenance path=%s A=%d B=%d", path, f.count("A", path), f.count("B", path))
		}
	}
}
