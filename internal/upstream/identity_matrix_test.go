package upstream

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// globalTestAuth 构造一个 global realm 的合成账号（只用于 realm 判定，无凭据）。
func globalTestAuth() *auth.Auth {
	a := &auth.Auth{UID: "u-global", Domain: "www.workbuddy.ai"}
	a.BackfillRealm()
	return a
}

// cnTestAuth 构造一个 CN realm 的合成账号。
func cnTestAuth() *auth.Auth {
	a := &auth.Auth{UID: "u-cn", Domain: "copilot.tencent.com"}
	a.BackfillRealm()
	return a
}

// chatHeaderSet 用空 clientIP/零值 meta 跑一遍 ChatHeaders，返回请求头。
func chatHeaderSet(t *testing.T, c *Client, a *auth.Auth) http.Header {
	t.Helper()
	r, err := http.NewRequest("POST", "https://fixture.invalid/v2/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.ChatHeaders(r, a, "", ChatMeta{ConversationRequestID: "00112233445566778899aabbccddeeff"})
	return r.Header
}

// TestIdentityMatrixUserAgentTable 身份矩阵 UA 取值表（规格 §2 取值表 + §6 用例 1）。
// 证据：E1（global 5.8.4 抓包）/ E3（CN 保持 5.5.6 实测，零漂移）。
func TestIdentityMatrixUserAgentTable(t *testing.T) {
	c := New()
	for _, tc := range []struct {
		name string
		a    *auth.Auth
		want string
	}{
		{"cn", cnTestAuth(), "WorkBuddy/5.5.6 WorkBuddy/5.5.6 CLI/2.137.1"},
		{"global", globalTestAuth(), "WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.userAgent(tc.a); got != tc.want {
				t.Fatalf("userAgent(%s) = %q want %q", tc.name, got, tc.want)
			}
			if got := c.defaultWorkBuddyUAFor(tc.a); got != tc.want {
				t.Fatalf("defaultWorkBuddyUAFor(%s) = %q want %q", tc.name, got, tc.want)
			}
			spec := c.desktopSpec(tc.a).UserAgent
			if spec != tc.want {
				t.Fatalf("desktopSpec(%s).UserAgent = %q want %q", tc.name, spec, tc.want)
			}
		})
	}
}

// TestIdentityMatrixCNZeroDrift CN 归属头零漂移（规格 §6 用例 2）：
// 头集合与取值保持升级前形态，且**不得**新增 X-Agent-Intent / X-Agent-Type /
// X-Private-Data —— CN 侧抓包从未出现这三个头（E3）。
func TestIdentityMatrixCNZeroDrift(t *testing.T) {
	c := New()
	h := chatHeaderSet(t, c, cnTestAuth())

	for k, want := range map[string]string{
		"X-Product":           "WorkBuddy",
		"X-Agent-Purpose":     "conversation",
		"X-IDE-Name":          "WorkBuddy",
		"X-IDE-Type":          "WorkBuddy",
		"X-IDE-Version":       "5.5.6",
		"User-Agent":          "WorkBuddy/5.5.6 WorkBuddy/5.5.6 CLI/2.137.1",
		"Accept-Language":     "zh-CN",
		"Origin":              "https://www.codebuddy.cn",
		"Referer":             "https://www.codebuddy.cn/",
		"X-CodeBuddy-Request": "1",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("CN %s = %q want %q", k, got, want)
		}
	}
	for _, banned := range []string{"X-Agent-Intent", "X-Agent-Type", "X-Private-Data"} {
		if v := h.Get(banned); v != "" {
			t.Errorf("CN must not send %s (got %q)", banned, v)
		}
	}
}

// TestIdentityMatrixGlobalUpgrade global 身份升级（规格 §6 用例 3，证据 E1）：
// 版本 5.8.4 / 品牌段 workbuddy-ai / 三个归属头 + 私有数据声明 / 国际版域与语言。
func TestIdentityMatrixGlobalUpgrade(t *testing.T) {
	c := New()
	h := chatHeaderSet(t, c, globalTestAuth())

	for k, want := range map[string]string{
		"User-Agent":      "WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0",
		"X-Product":       "SaaS",
		"X-Agent-Purpose": "conversation",
		"X-Agent-Intent":  "craft",
		"X-Agent-Type":    "main",
		"X-Private-Data":  "true",
		"X-IDE-Name":      "WorkBuddy",
		"X-IDE-Type":      "WorkBuddy",
		"X-IDE-Version":   "5.8.4",
		"X-Domain":        "www.workbuddy.ai",
		"Origin":          "https://www.workbuddy.ai",
		"Referer":         "https://www.workbuddy.ai/",
		"Accept-Language": "en-US",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("global %s = %q want %q", k, got, want)
		}
	}
}

// TestIdentityMatrixOverridePrecedence 显式 config 优先于矩阵默认（规格 §6 用例 4）：
// client_version 同时改 UA 两处版本段与 X-IDE-Version；cli_version 只改 CLI 段；
// user_agent 整段覆盖。
func TestIdentityMatrixOverridePrecedence(t *testing.T) {
	// 1) ClientVersion 覆盖：CN 5.5.6 → 6.0.0（UA 两段 + X-IDE-Version 同步）。
	c := &Client{ClientVersion: "6.0.0"}
	h := chatHeaderSet(t, c, cnTestAuth())
	if got := h.Get("User-Agent"); got != "WorkBuddy/6.0.0 WorkBuddy/6.0.0 CLI/2.137.1" {
		t.Errorf("client_version UA = %q", got)
	}
	if got := h.Get("X-IDE-Version"); got != "6.0.0" {
		t.Errorf("client_version X-IDE-Version = %q", got)
	}

	// 2) CliVersion 覆盖：只改 CLI 段，客户端版本仍取矩阵默认。
	c = &Client{CliVersion: "9.9.9"}
	h = chatHeaderSet(t, c, globalTestAuth())
	if got := h.Get("User-Agent"); got != "WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/9.9.9" {
		t.Errorf("cli_version UA = %q", got)
	}

	// 3) UserAgent 整段覆盖：三处头都不再出现矩阵默认 UA。
	c = &Client{UserAgent: "CustomAgent/1"}
	h = chatHeaderSet(t, c, cnTestAuth())
	if got := h.Get("User-Agent"); got != "CustomAgent/1" {
		t.Errorf("user_agent UA = %q", got)
	}
}

// TestIdentityMatrixBillingSurface billing 域头面（规格 §6 用例 5）：
// 不注入 X-Machine-ID / X-Session-ID / Origin / Referer；UA 退化为单段短形态；
// 显式 client_name="SaaS" 才不设 UA（还原旧行为）。
func TestIdentityMatrixBillingSurface(t *testing.T) {
	c := New()
	r, _ := http.NewRequest("POST", "https://fixture.invalid/billing", nil)
	c.BillingHeaders(r, globalTestAuth())
	h := r.Header
	if got := h.Get("User-Agent"); got != "WorkBuddy/5.8.4" {
		t.Errorf("billing UA = %q want WorkBuddy/5.8.4", got)
	}
	for _, absent := range []string{"X-Machine-ID", "X-Session-ID", "Origin", "Referer", "X-Agent-Intent", "X-Private-Data"} {
		if v := h.Get(absent); v != "" {
			t.Errorf("billing must not send %s (got %q)", absent, v)
		}
	}
	c.ClientName = "SaaS"
	if got := c.billingUA(); got != "" {
		t.Errorf("billingUA() with client_name=SaaS = %q want empty", got)
	}
}

// captureDesktopReport 启动一个捕获 /v2/report 的假上游，返回请求头 UA 与事件体。
func captureDesktopReport(t *testing.T, a *auth.Auth) (string, map[string]any) {
	t.Helper()
	var ua string
	var events []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &events); err != nil {
			t.Errorf("report body must be array: %v", err)
		}
		// 规格 §3：/v2/report 没有抓包证据支持 X-Private-Data，不得新增。
		if v := r.Header.Get("X-Private-Data"); v != "" {
			t.Errorf("/v2/report must not send X-Private-Data (got %q)", v)
		}
		w.Write([]byte(`{"code":0,"msg":"OK"}`))
	}))
	defer srv.Close()
	c := New()
	c.HTTP, c.ChatHTTP, c.ChatBaseCN, c.ChatBaseGlobal = srv.Client(), srv.Client(), srv.URL, srv.URL
	if err := c.ReportDesktopEvent(a, DesktopEvent{"eventCode": "agent_task_created"}); err != nil {
		t.Fatalf("report desktop: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
	return ua, events[0]
}

// TestIdentityMatrixDesktopReportVersion 桌面上报体的版本字段按 realm 走矩阵
// （规格 §6 用例 6）：CN 5.5.6 / global 5.8.4，且 body 形状不变。
func TestIdentityMatrixDesktopReportVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		a       *auth.Auth
		version string
		ua      string
	}{
		{"cn", cnTestAuth(), "5.5.6", "WorkBuddy/5.5.6 WorkBuddy/5.5.6 CLI/2.137.1"},
		{"global", globalTestAuth(), "5.8.4", "WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ua, ev := captureDesktopReport(t, tc.a)
			if ua != tc.ua {
				t.Errorf("report UA = %q want %q", ua, tc.ua)
			}
			if ev["ideVersion"] != tc.version || ev["extVersion"] != tc.version {
				t.Errorf("report version = %v/%v want %s", ev["ideVersion"], ev["extVersion"], tc.version)
			}
			// 其余指纹字段形状不变。
			if ev["ideName"] != "WorkBuddy" || ev["ideType"] != "WorkBuddy" || ev["product"] != "SaaS" {
				t.Errorf("desktop fingerprint drifted: %v", ev)
			}
		})
	}
}

// TestIdentityMatrixMPVersion 小程序端版本不变（规格 §6 用例 7）：ideVersion /
// extVersion / X-Client-Version 均为 2.4.0（本次只改 machineId 来源，见 device_identity_test）。
func TestIdentityMatrixMPVersion(t *testing.T) {
	var body []map[string]any
	var clientVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientVersion = r.Header.Get("X-Client-Version")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("mp report body must be array: %v", err)
		}
		w.Write([]byte(`{"code":0,"msg":"OK"}`))
	}))
	defer srv.Close()
	c := New()
	c.HTTP, c.ChatHTTP, c.BillingBaseCN = srv.Client(), srv.Client(), srv.URL
	if err := c.ReportMPEvent(cnTestAuth(), map[string]any{"eventCode": "chat_request_send"}); err != nil {
		t.Fatalf("report mp: %v", err)
	}
	if clientVersion != "2.4.0" {
		t.Errorf("X-Client-Version = %q want 2.4.0", clientVersion)
	}
	if len(body) != 1 || body[0]["ideVersion"] != "2.4.0" || body[0]["extVersion"] != "2.4.0" {
		t.Fatalf("mp version fields drifted: %v", body)
	}
	// 身份态字段（ideType/ideName/product）保持小程序实测形态。
	if body[0]["ideType"] != "WorkBuddy_MP" || body[0]["ideName"] != "wx_app_cloud" || body[0]["product"] != "SaaS" {
		t.Errorf("mp identity fields drifted: %v", body[0])
	}
}
