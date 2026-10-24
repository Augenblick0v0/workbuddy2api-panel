package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func pinPoolFixture(t *testing.T) (*Handler, *pool.Pool) {
	t.Helper()
	c := upstream.New()
	c.ChatBaseCN = "http://upstream.invalid"
	p := pool.New("")
	p.Add(&auth.Auth{UID: "uid-alpha-1111", Nickname: "alpha", AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	p.Add(&auth.Auth{UID: "uid-beta-2222", Nickname: "beta", AccessToken: "b", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	p.SetRouteAvailable(func(string) bool { return true })
	return NewHandler(Config{Pool: p, Upstream: c, MaxRotate: 1}), p
}

func TestResolveAccountRef(t *testing.T) {
	h, _ := pinPoolFixture(t)
	if got := h.resolveAccountRef("uid-alpha-1111"); got != "uid-alpha-1111" {
		t.Fatalf("exact uid = %q", got)
	}
	if got := h.resolveAccountRef("uid-beta"); got != "uid-beta-2222" {
		t.Fatalf("unique prefix = %q", got)
	}
	if got := h.resolveAccountRef("alpha"); got != "uid-alpha-1111" {
		t.Fatalf("unique nickname = %q", got)
	}
	if got := h.resolveAccountRef("uid-"); got != "" {
		t.Fatalf("ambiguous prefix must resolve empty, got %q", got)
	}
	if got := h.resolveAccountRef("nobody"); got != "" {
		t.Fatalf("no match must be empty, got %q", got)
	}
}

func TestPinnedRouteRejectsUnknownRef(t *testing.T) {
	h, _ := pinPoolFixture(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/u/nobody/v1/chat/completions",
		strings.NewReader(`{"model":"glm-5.2","messages":[{"role":"user","content":"x"}]}`)))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "account_ref_not_found") {
		t.Fatalf("unknown ref = %d %s", w.Code, w.Body.String())
	}
}

func TestModelAllowlist(t *testing.T) {
	h, _ := pinPoolFixture(t)
	h.cfg.ModelsAllowlist = []string{"glm-5.2"}
	if !h.modelAllowed("glm-5.2") || !h.modelAllowed("glm-5.2-flash") {
		t.Fatal("allowlist boundary prefix must match")
	}
	if h.modelAllowed("glm-5.20") || h.modelAllowed("gpt-6-sol") {
		t.Fatal("allowlist must not over-match")
	}
	if bareModelName("cn:glm-5.2") != "glm-5.2" || bareModelName("glm-5.2") != "glm-5.2" {
		t.Fatal("bareModelName must strip realm prefix")
	}
	// chat 请求名单外模型 → 403。
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-6-sol","messages":[{"role":"user","content":"x"}]}`)))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "model_not_allowed") {
		t.Fatalf("disallowed model = %d %s", w.Code, w.Body.String())
	}
}
