package panel

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// 「上游拒绝授权」的回归面：CN 版登录在浏览器里还没点完时，上游回的是
// HTTP 200 + code 11217（msg 文案随版本漂移，线上是 "login ing..."）。
// 判定必须以业务码为准，否则用户刚点登录就立刻看到失败。
func TestOAuthPendingCodesAreUpstreamDriven(t *testing.T) {
	pollResult := func(t *testing.T, f *oauthPendingFixture) (int, map[string]any) {
		t.Helper()
		w := f.poll(t)
		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		return w.Code, got
	}

	t.Run("token-11217-real-message", func(t *testing.T) {
		f := newOAuthPendingFixture(t)
		f.mu.Lock()
		f.bodies["/token"] = `{"code":11217,"msg":"login ing..."}`
		f.mu.Unlock()
		if w := f.start(t); w.Code != 200 {
			t.Fatalf("start: %d %s", w.Code, w.Body)
		}
		if code, got := pollResult(t, f); code != 200 || got["done"] != false || got["message"] != "waiting_for_login" {
			t.Fatalf("real CN pending must wait, not fail: %d %v", code, got)
		}
		f.mu.Lock()
		f.bodies["/token"] = `{"code":0,"data":{"accessToken":"private-fixture-token","refreshToken":"private-fixture-refresh","expiresIn":3600}}`
		f.mu.Unlock()
		assertOAuthDone(t, f.poll(t))
	})

	t.Run("token-11217-message-drift", func(t *testing.T) {
		f := newOAuthPendingFixture(t)
		f.mu.Lock()
		f.bodies["/token"] = `{"code":11217,"msg":"account access restricted"}`
		f.mu.Unlock()
		if w := f.start(t); w.Code != 200 {
			t.Fatalf("start: %d %s", w.Code, w.Body)
		}
		// 码是 11217 就是「还没好」：文案不是判据，换个说法也不能判死会话。
		if code, got := pollResult(t, f); code != 200 || got["done"] != false {
			t.Fatalf("11217 must stay pending whatever the msg says: %d %v", code, got)
		}
	})

	t.Run("account-12151-waits-then-completes", func(t *testing.T) {
		f := newOAuthPendingFixture(t)
		f.mu.Lock()
		f.bodies["/account"] = `{"code":12151,"msg":"account ing..."}`
		f.mu.Unlock()
		if w := f.start(t); w.Code != 200 {
			t.Fatalf("start: %d %s", w.Code, w.Body)
		}
		if code, got := pollResult(t, f); code != 200 || got["done"] != false {
			t.Fatalf("authorized token but pending account must wait: %d %v", code, got)
		}
		// 会话不能被判死：账号信息到位后同一 state 直接完成。
		if w := f.poll(t); w.Code != 200 {
			t.Fatalf("pending account killed the session: %d %s", w.Code, w.Body)
		}
		f.mu.Lock()
		f.bodies["/account"] = `{"code":0,"data":{"uid":"oauth-fixture-uid","nickname":"synthetic"}}`
		f.mu.Unlock()
		assertOAuthDone(t, f.poll(t))
	})

	t.Run("account-11217-is-terminal", func(t *testing.T) {
		f := newOAuthPendingFixture(t)
		f.mu.Lock()
		f.bodies["/account"] = `{"code":11217,"msg":"login ing..."}`
		f.mu.Unlock()
		if w := f.start(t); w.Code != 200 {
			t.Fatalf("start: %d %s", w.Code, w.Body)
		}
		// token 的等待码不适用于 account 阶段：仍然是业务错误。
		if code, got := pollResult(t, f); code != 502 || got["code"] != "oauth_upstream_failed" || got["stage"] != "account" {
			t.Fatalf("token-only pending code must not leak into account stage: %d %v", code, got)
		}
	})
}

// 登录身份必须是官方 WorkBuddy 桌面端，而不是 CodeBuddy CLI：两者在 CN 会被
// 派到不同的登录页（见 loginEndpoints 注释），身份错位就是「上游拒绝授权」的根。
func TestOAuthLoginIdentityMatchesDesktopApp(t *testing.T) {
	f := newOAuthPendingFixture(t)
	start := f.start(t)
	if start.Code != 200 {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	var out struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(start.Body.Bytes(), &out) != nil || out.URL == "" {
		t.Fatalf("start body: %s", start.Body)
	}
	authURL, err := url.Parse(out.URL)
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	q := authURL.Query()
	if q.Get("version") != clientAppVersion {
		t.Errorf("authUrl version=%q want %q", q.Get("version"), clientAppVersion)
	}
	if len(q.Get("loginSessionId")) != 32 {
		t.Errorf("authUrl loginSessionId=%q want 32 hex chars", q.Get("loginSessionId"))
	}

	f.mu.Lock()
	stateH := f.headers["/state"].Clone()
	f.mu.Unlock()
	if got := stateH.Get("User-Agent"); got != "WorkBuddy/"+clientAppVersion {
		t.Errorf("state UA=%q want desktop UA", got)
	}
	for _, h := range []string{"Origin", "Referer", "X-Requested-With"} {
		if stateH.Get(h) != "" {
			t.Errorf("state must not send browser header %s=%q", h, stateH.Get(h))
		}
	}
	for _, h := range []string{"X-No-Authorization", "X-No-User-Id", "X-No-Enterprise-Id", "X-No-Department-Info"} {
		if stateH.Get(h) != "true" {
			t.Errorf("state missing %s: %q", h, stateH.Get(h))
		}
	}
	if got := stateH.Get("Authorization"); got != "" {
		t.Errorf("state must not carry Authorization: %q", got)
	}

	if w := f.poll(t); w.Code != 200 {
		t.Fatalf("poll: %d %s", w.Code, w.Body)
	}
	f.mu.Lock()
	tokenH := f.headers["/token"].Clone()
	accountH := f.headers["/account"].Clone()
	f.mu.Unlock()
	for name, h := range map[string]http.Header{"/token": tokenH, "/account": accountH} {
		if got := h.Get("User-Agent"); got != "WorkBuddy/"+clientAppVersion {
			t.Errorf("%s UA=%q want desktop UA", name, got)
		}
		if h.Get("X-No-Authorization") != "" {
			t.Errorf("%s must not send X-No-Authorization (it would void the bearer)", name)
		}
	}
	if got := tokenH.Get("Authorization"); got != "" {
		t.Errorf("token poll must stay anonymous: %q", got)
	}
	if got := accountH.Get("Authorization"); got != "Bearer private-fixture-token" {
		t.Errorf("account poll bearer=%q", got)
	}
	if got := accountH.Get("X-Domain"); got == "" || strings.Contains(got, "://") {
		t.Errorf("account poll X-Domain=%q want a bare host", got)
	}
}
