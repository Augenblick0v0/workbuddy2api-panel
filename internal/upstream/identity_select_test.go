package upstream

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func selAuth(uid, domain string) *auth.Auth {
	a := &auth.Auth{UID: uid, Domain: domain}
	a.BackfillRealm()
	return a
}

func TestOutboundIdentitySelection(t *testing.T) {
	c := &Client{}
	if got := c.outboundIdentityFor(selAuth("u1", "copilot.tencent.com")); got != OutboundIdentityDesktop {
		t.Fatalf("default identity = %q, want desktop", got)
	}
	c.OutboundIdentity = "cli"
	if got := c.outboundIdentityFor(nil); got != OutboundIdentityCLI {
		t.Fatalf("static cli = %q", got)
	}
	c.OutboundIdentity = OutboundIdentityAuto
	if got := c.outboundIdentityFor(nil); got != OutboundIdentityDesktop {
		t.Fatalf("auto with empty allowlist = %q, want desktop", got)
	}
	c.OutboundIdentityAllowedList = []string{"desktop", "cli", "vscode", "bogus"}
	first := c.outboundIdentityFor(selAuth("u-cn", "copilot.tencent.com"))
	if first == OutboundIdentityDesktop && c.outboundIdentityFor(selAuth("u-cn2", "copilot.tencent.com")) == OutboundIdentityDesktop {
		t.Fatal("auto should spread identities across accounts (both picked desktop)")
	}
	for i := 0; i < 3; i++ {
		if again := c.outboundIdentityFor(selAuth("u-cn", "copilot.tencent.com")); again != first {
			t.Fatalf("auto identity not stable per uid: %q then %q", first, again)
		}
	}
}

func chatHeadersFor(t *testing.T, c *Client, a *auth.Auth, meta ChatMeta) http.Header {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "https://fixture.invalid/v2/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.ChatHeaders(r, a, "", meta)
	return r.Header
}

func TestChatHeadersCLIIdentity(t *testing.T) {
	c := &Client{OutboundIdentity: OutboundIdentityCLI}
	h := chatHeadersFor(t, c, selAuth("u1", "copilot.tencent.com"), ChatMeta{ConversationRequestID: "req1"})
	if got := h.Get("User-Agent"); got != "CLI/2.168.2 CodeBuddy/2.168.2" {
		t.Fatalf("cli UA = %q", got)
	}
	if h.Get("X-IDE-Type") != "CLI" || h.Get("X-IDE-Name") != "CLI" || h.Get("X-IDE-Version") != "2.168.2" {
		t.Fatalf("cli X-IDE-* wrong: %q %q %q", h.Get("X-IDE-Type"), h.Get("X-IDE-Name"), h.Get("X-IDE-Version"))
	}
	if h.Get("X-Agent-Runtime") != "other" {
		t.Fatalf("X-Agent-Runtime = %q", h.Get("X-Agent-Runtime"))
	}
	// 小写 wire：stainless 头直接下 map（Header.Get 的规范化键查不到它们＝
	// 未被 Set 驼峰化，正是官方 wire 的小写形态）。
	if v := h["x-stainless-lang"]; v == nil || v[0] != "js" {
		t.Fatalf("x-stainless-lang missing: %v", h["x-stainless-lang"])
	}
	if v := h["x-stainless-runtime-version"]; v == nil || v[0] == "" {
		t.Fatal("x-stainless-runtime-version missing")
	}
	if h.Get("X-Private-Data") != "false" {
		t.Fatalf("personal account X-Private-Data = %q, want false", h.Get("X-Private-Data"))
	}
	ent := selAuth("u1", "copilot.tencent.com")
	ent.EnterpriseID = "ent-1"
	he := chatHeadersFor(t, c, ent, ChatMeta{})
	if he.Get("X-Private-Data") != "true" {
		t.Fatalf("enterprise X-Private-Data = %q, want true", he.Get("X-Private-Data"))
	}
}

func TestChatHeadersVSCodeIdentity(t *testing.T) {
	c := &Client{OutboundIdentity: OutboundIdentityVSCode}
	h := chatHeadersFor(t, c, selAuth("u1", "copilot.tencent.com"), ChatMeta{ConversationRequestID: "req9", Model: "glm-5.2"})
	if got := h.Get("User-Agent"); got != "VSCode/1.119.0 CodeBuddy/4.12.39997873" {
		t.Fatalf("vscode UA = %q", got)
	}
	if h.Get("X-Env-ID") != "production" || h.Get("X-Product-Version") != "4.12.39997873" {
		t.Fatalf("vscode env/product headers wrong")
	}
	// CN 账号：官方 VSCode 在国内站不发 X-Private-Data。
	if _, ok := h["X-Private-Data"]; ok {
		t.Fatal("vscode CN must omit X-Private-Data")
	}
	if v := h.Get("X-Request-Trace-Id"); len(v) != 36 || v[8] != '-' || v[13] != '-' {
		t.Fatalf("X-Request-Trace-Id not hyphenated UUID: %q", v)
	}
	if h.Get("X-Request-ID") != "req9" {
		t.Fatalf("vscode X-Request-ID = %q, want the turn request id", h.Get("X-Request-ID"))
	}
	if _, ok := h["X-Root-Request-Id"]; ok {
		t.Fatal("vscode primary agent must not send X-Root-Request-ID")
	}
	if h.Get("X-Model-ID") != "glm-5.2" || h.Get("monitor_httpSendTime") == "" {
		t.Fatalf("vscode model headers missing: %q", h.Get("X-Model-ID"))
	}
	g := chatHeadersFor(t, c, selAuth("g1", "www.workbuddy.ai"), ChatMeta{})
	if g.Get("X-Private-Data") != "true" {
		t.Fatalf("vscode global X-Private-Data = %q, want true", g.Get("X-Private-Data"))
	}
}

func TestCLIChatBody(t *testing.T) {
	in := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"metadata":{"a":1},"conversation_id":"c1","previous_response_id":"r1","stream":true}`)
	out := cliChatBody(in)
	if out[0] != 0x1f || out[1] != 0x8b {
		t.Fatalf("cli body not gzip (magic %x %x)", out[0], out[1])
	}
	zr, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("gunzipped body not json: %v", err)
	}
	for _, gone := range []string{"metadata", "conversation_id", "previous_response_id"} {
		if _, ok := obj[gone]; ok {
			t.Fatalf("cli body still carries %q", gone)
		}
	}
	if obj["cache_retention"] != "long" {
		t.Fatalf("cache_retention = %v, want long", obj["cache_retention"])
	}
	if obj["model"] != "glm-5.2" {
		t.Fatalf("model field lost: %v", obj["model"])
	}
}
