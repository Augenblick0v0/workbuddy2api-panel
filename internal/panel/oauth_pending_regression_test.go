package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// This reproduces the production CN explicit-direct response without any real
// identity, state, cookies, credentials, or upstream network access.
func TestOAuthCNExplicitDirectPending11217KeepsSession(t *testing.T) {
	var approved atomic.Bool
	var accountCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/state":
			w.Write([]byte(`{"code":0,"data":{"state":"synthetic-pending-state","authUrl":"https://browser.fixture.invalid/authorize"}}`))
		case "/token":
			if !approved.Load() {
				w.Write([]byte(`{"code":11217,"msg":"11217:login ing..."}`))
				return
			}
			w.Write([]byte(`{"code":0,"data":{"accessToken":"synthetic-access","refreshToken":"synthetic-refresh","expiresIn":3600}}`))
		case "/account":
			accountCalls.Add(1)
			w.Write([]byte(`{"code":0,"data":{"uid":"cn-direct-fixture","nickname":"synthetic"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()
	dir := t.TempDir()
	manager, err := egress.Open(filepath.Join(dir, "proxies.json"), egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.CloseIdleConnections()
	pl := pool.New("")
	pn := New(Config{
		Pool: pl, Egress: manager, APIKey: "key", AuthDir: filepath.Join(dir, "auths"),
		LoginEndpoints: func(string) (string, string, string, string) {
			return target.URL + "/state", target.URL + "/token?state=", target.URL + "/account?state=", target.URL
		},
	})
	start := proxyCall(t, pn, "POST", "/panel/api/login/start", `{"realm":"cn","proxy_slot_id":""}`, "http://panel.test")
	if start.Code != 200 {
		t.Fatalf("start status=%d body=%s", start.Code, start.Body)
	}
	for n := 0; n < 2; n++ {
		poll := proxyCall(t, pn, "GET", "/panel/api/login/poll?state=synthetic-pending-state", "", "")
		var result struct {
			Done bool `json:"done"`
		}
		if poll.Code != 200 || json.Unmarshal(poll.Body.Bytes(), &result) != nil || result.Done {
			t.Fatalf("pending11217 must keep the same session, got status=%d body=%s", poll.Code, poll.Body)
		}
		if accountCalls.Load() != 0 || pl.AuthByUID("cn-direct-fixture") != nil {
			t.Fatal("unapproved session must not fetch account or publish credentials")
		}
	}
	approved.Store(true)
	done := proxyCall(t, pn, "GET", "/panel/api/login/poll?state=synthetic-pending-state", "", "")
	var result struct {
		Done bool   `json:"done"`
		UID  string `json:"uid"`
	}
	if done.Code != 200 || json.Unmarshal(done.Body.Bytes(), &result) != nil || !result.Done || result.UID != "cn-direct-fixture" {
		t.Fatalf("approved pending session did not complete: status=%d body=%s", done.Code, done.Body)
	}
	snapshot := manager.Snapshot()
	slot, exists := snapshot.Bindings["cn-direct-fixture"]
	if !exists || slot != "" || pl.AuthByUID("cn-direct-fixture") == nil {
		t.Fatal("successful direct OAuth must persist explicit-direct binding before account publication")
	}
}

type oauthPendingFixture struct {
	panel   *Panel
	manager *egress.Manager
	mu      sync.Mutex
	calls   map[string]int
	status  map[string]int
	bodies  map[string]string
	retry   string
}

func newOAuthPendingFixture(t *testing.T) *oauthPendingFixture {
	t.Helper()
	f := &oauthPendingFixture{
		calls: map[string]int{}, status: map[string]int{}, bodies: map[string]string{
			"/state":   `{"code":0,"data":{"state":"sensitive-fixture-state","authUrl":"https://browser.fixture.invalid/private"}}`,
			"/token":   `{"code":0,"data":{"accessToken":"private-fixture-token","refreshToken":"private-fixture-refresh","expiresIn":3600}}`,
			"/account": `{"code":0,"data":{"uid":"oauth-fixture-uid","nickname":"synthetic"}}`,
		},
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		if f.retry != "" {
			w.Header().Set("Retry-After", f.retry)
		}
		status := f.status[r.URL.Path]
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		w.Write([]byte(f.bodies[r.URL.Path]))
	}))
	t.Cleanup(target.Close)
	dir := t.TempDir()
	m, err := egress.Open(filepath.Join(dir, "proxies.json"), egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f.manager = m
	t.Cleanup(m.CloseIdleConnections)
	f.panel = New(Config{Pool: pool.New(""), Egress: m, APIKey: "key", AuthDir: filepath.Join(dir, "auths"),
		LoginEndpoints: func(string) (string, string, string, string) {
			return target.URL + "/state", target.URL + "/token?state=", target.URL + "/account?state=", target.URL
		},
	})
	t.Cleanup(func() {
		proxyCall(t, f.panel, http.MethodPost, "/panel/api/login/cancel", `{"state":"sensitive-fixture-state"}`, "http://panel.test")
	})
	return f
}

func (f *oauthPendingFixture) start(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return proxyCall(t, f.panel, http.MethodPost, "/panel/api/login/start", `{"realm":"cn","proxy_slot_id":""}`, "http://panel.test")
}

func (f *oauthPendingFixture) poll(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return proxyCall(t, f.panel, http.MethodGet, "/panel/api/login/poll?state=sensitive-fixture-state", "", "")
}

func (f *oauthPendingFixture) allowNextPoll(t *testing.T) {
	t.Helper()
	f.panel.loginMu.Lock()
	s := f.panel.logins["sensitive-fixture-state"]
	f.panel.loginMu.Unlock()
	if s == nil {
		t.Fatal("OAuth session disappeared")
	}
	s.mu.Lock()
	s.nextPollAt = time.Time{}
	s.mu.Unlock()
}

func TestOAuthPendingIsSpecificToTokenStageAndKnownResponse(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
	}{
		{"state", "/state", `{"code":11217,"msg":"11217:login ing..."}`},
		{"account", "/account", `{"code":11217,"msg":"11217:login ing..."}`},
		{"legacy-account", "/account", `{"code":1,"msg":"pending"}`},
		{"unknown-code", "/token", `{"code":999,"msg":"11217:login ing..."}`},
		{"same-code-rejected", "/token", `{"code":11217,"msg":"account access restricted"}`},
		{"unknown-error", "/token", `{"code":999,"msg":"private-fixture-token sensitive-fixture-state https://browser.fixture.invalid/private"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOAuthPendingFixture(t)
			f.mu.Lock()
			f.bodies[tc.path] = tc.body
			f.mu.Unlock()
			w := f.start(t)
			if tc.path != "/state" {
				if w.Code != 200 {
					t.Fatalf("start: %d %s", w.Code, w.Body)
				}
				w = f.poll(t)
			}
			var got map[string]any
			json.Unmarshal(w.Body.Bytes(), &got)
			if w.Code != 502 || got["code"] != "oauth_upstream_failed" || got["category"] != "business" || got["upstream_status"] != float64(200) {
				t.Fatalf("non-token/unknown business error must be terminal with safe diagnostics: %d %s", w.Code, w.Body)
			}
			for _, secret := range []string{"sensitive-fixture-state", "private-fixture-token", "browser.fixture.invalid", "access restricted"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("OAuth failure leaked upstream state/message/token")
				}
			}
			if tc.path != "/state" {
				f.mu.Lock()
				before := f.calls["/token"] + f.calls["/account"]
				f.mu.Unlock()
				if w = f.poll(t); w.Code != 409 {
					t.Fatalf("terminal session continued: %d %s", w.Code, w.Body)
				}
				f.mu.Lock()
				after := f.calls["/token"] + f.calls["/account"]
				f.mu.Unlock()
				if before != after {
					t.Fatal("terminal session replayed upstream requests")
				}
			}
			if len(f.manager.Snapshot().Bindings) != 0 || len(f.panel.cfg.Pool.List()) != 0 {
				t.Fatal("failed OAuth must not publish binding or account")
			}
		})
	}
}

func TestOAuthTokenTransientRetryIsBoundedAndHonorsWait(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newOAuthPendingFixture(t)
			f.mu.Lock()
			f.status["/token"], f.retry = status, "9"
			f.mu.Unlock()
			if w := f.start(t); w.Code != 200 {
				t.Fatalf("start: %d %s", w.Code, w.Body)
			}
			for attempt := 0; attempt < loginMaxTransient; attempt++ {
				w := f.poll(t)
				var result struct {
					Done       bool   `json:"done"`
					Message    string `json:"message"`
					RetryAfter int    `json:"retry_after"`
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Done || result.Message != "upstream_retry_wait" || result.RetryAfter < 9 || result.RetryAfter > loginMaxRetryWait {
					t.Fatalf("transient retry: %d %s", w.Code, w.Body)
				}
				f.mu.Lock()
				before := f.calls["/token"]
				f.mu.Unlock()
				w = f.poll(t)
				f.mu.Lock()
				after := f.calls["/token"]
				f.mu.Unlock()
				if w.Code != 200 || before != after {
					t.Fatal("early poll bypassed retry wait")
				}
				f.allowNextPoll(t)
			}
			if w := f.poll(t); w.Code != 502 {
				t.Fatalf("transient retry budget was not bounded: %d %s", w.Code, w.Body)
			}
			if w := f.poll(t); w.Code != 409 {
				t.Fatalf("exhausted session kept polling: %d %s", w.Code, w.Body)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.calls["/token"] != loginMaxTransient+1 || f.calls["/account"] != 0 {
				t.Fatal("unexpected retry count or account request")
			}
		})
	}
}

func TestOAuthTransientTokenCanRecoverButOtherStagesCannotReplay(t *testing.T) {
	t.Run("token-recovers-in-same-session", func(t *testing.T) {
		f := newOAuthPendingFixture(t)
		f.mu.Lock()
		f.status["/token"] = 503
		f.mu.Unlock()
		if w := f.start(t); w.Code != 200 {
			t.Fatal(w.Body)
		}
		if w := f.poll(t); w.Code != 200 || !strings.Contains(w.Body.String(), "upstream_retry_wait") {
			t.Fatalf("transient token: %d %s", w.Code, w.Body)
		}
		f.mu.Lock()
		f.status["/token"] = 0
		f.mu.Unlock()
		f.allowNextPoll(t)
		assertOAuthDone(t, f.poll(t))
	})
	for _, stage := range []string{"/state", "/account"} {
		t.Run(stage, func(t *testing.T) {
			f := newOAuthPendingFixture(t)
			f.mu.Lock()
			f.status[stage] = 503
			f.mu.Unlock()
			w := f.start(t)
			if stage == "/account" {
				w = f.poll(t)
			}
			if w.Code != 502 {
				t.Fatalf("state/account failure must not be retried: %d %s", w.Code, w.Body)
			}
			if stage == "/account" {
				if w = f.poll(t); w.Code != 409 {
					t.Fatal("account-stage failure replayed token/account")
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.calls[stage] != 1 {
				t.Fatal("state/account stage replayed automatically")
			}
		})
	}
}

func TestOAuthRetryAfterLongWaitStopsRatherThanRetryingEarly(t *testing.T) {
	f := newOAuthPendingFixture(t)
	f.mu.Lock()
	f.status["/token"], f.retry = 429, "120"
	f.mu.Unlock()
	if w := f.start(t); w.Code != 200 {
		t.Fatal(w.Body)
	}
	if w := f.poll(t); w.Code != 502 {
		t.Fatalf("unbounded Retry-After must not schedule an early retry: %d %s", w.Code, w.Body)
	}
}

func TestOAuthRetryWaitStillChecksCancellationAndRouteGeneration(t *testing.T) {
	for _, change := range []string{"cancel", "expired", "route"} {
		t.Run(change, func(t *testing.T) {
			f := newOAuthPendingFixture(t)
			f.mu.Lock()
			f.status["/token"] = 503
			f.mu.Unlock()
			if w := f.start(t); w.Code != 200 {
				t.Fatal(w.Body)
			}
			if w := f.poll(t); w.Code != 200 {
				t.Fatal(w.Body)
			}
			f.panel.loginMu.Lock()
			sess := f.panel.logins["sensitive-fixture-state"]
			f.panel.loginMu.Unlock()
			switch change {
			case "cancel":
				proxyCall(t, f.panel, http.MethodPost, "/panel/api/login/cancel", `{"state":"sensitive-fixture-state"}`, "http://panel.test")
			case "expired":
				sess.cancel()
			case "route":
				// Invalidating the pinned handle must still be checked before retry wait.
				sess.route.Release()
			}
			w := f.poll(t)
			if w.Code < 400 {
				t.Fatalf("inactive authorization remained in retry wait: %d %s", w.Code, w.Body)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.calls["/token"] != 1 || f.calls["/account"] != 0 {
				t.Fatal("inactive authorization retried upstream or published account")
			}
		})
	}
}

func TestOAuthRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		raw  string
		want int
	}{{"12", 12}, {"-1", 0}, {"bad", 0}, {now.Add(30 * time.Second).Format(http.TimeFormat), 30}, {now.Add(-time.Second).Format(http.TimeFormat), 0}} {
		if got := loginRetryAfter(tc.raw, now); got != tc.want {
			t.Fatalf("retry-after %q=%d, want %d", tc.raw, got, tc.want)
		}
	}
}
