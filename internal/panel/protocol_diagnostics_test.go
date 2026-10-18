package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

type diagnosticsTransport struct{ calls atomic.Int64 }

func (d *diagnosticsTransport) RoundTrip(*http.Request) (*http.Response, error) {
	d.calls.Add(1)
	return nil, errors.New("diagnostics must not make requests")
}

func diagnosticsCall(p *Panel, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/panel/api/protocol_diagnostics", nil)
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestProtocolDiagnosticsAuthAndUnavailableDependencies(t *testing.T) {
	p := New(Config{APIKey: "fixture-key"})
	for _, key := range []string{"", "wrong-key", "fixture-key"} {
		w := diagnosticsCall(p, key)
		want := 401
		if key == "fixture-key" {
			want = 501
		}
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("key=%q status=%d headers=%v", key, w.Code, w.Header())
		}
	}
	p = New(Config{Pool: pool.New(""), APIKey: "fixture-key"})
	if w := diagnosticsCall(p, "fixture-key"); w.Code != 501 {
		t.Fatal("missing upstream should be 501", w.Code)
	}
	p = New(Config{Upstream: &upstream.Client{}, APIKey: "fixture-key"})
	if w := diagnosticsCall(p, "fixture-key"); w.Code != 501 {
		t.Fatal("missing pool should be 501", w.Code)
	}
	p = New(Config{})
	if w := diagnosticsCall(p, ""); w.Code != 503 {
		t.Fatal("empty key permits unauthenticated diagnostics", w.Code)
	}
}

func TestProtocolDiagnosticsOfflineRedactedRoutesAndSchema(t *testing.T) {
	pl := pool.New("")
	pl.Add(&auth.Auth{UID: "a", AccessToken: "synthetic-access-secret", RefreshToken: "synthetic-refresh-secret", DeviceToken: "synthetic-account-secret", FilePath: "/synthetic/credential-path"})
	pl.Add(&auth.Auth{UID: "b", Domain: "www.workbuddy.ai"})
	manager, err := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Update(0, func(c *egress.Config) error {
		c.NextSlotSeq = 2
		c.Slots["slot-1"] = egress.Slot{ID: "slot-1", Name: "fixture", Enabled: true, Scheme: "http", Host: "private-proxy.example", Port: 8080, Username: "synthetic-proxy-user", Password: "synthetic-proxy-password"}
		c.Bindings["a"] = "slot-1"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := &diagnosticsTransport{}
	c := &upstream.Client{
		HTTP: &http.Client{Transport: transport}, ChatHTTP: &http.Client{Transport: transport},
		PublicHTTP: &http.Client{Transport: transport}, DeviceToken: "synthetic-global-secret",
		DeviceTokenFile: "/synthetic/device-path", ClientVersion: "fixture-client", CliVersion: "fixture-cli",
	}
	p := New(Config{Pool: pl, Egress: manager, Upstream: c, APIKey: "fixture-key"})
	w := diagnosticsCall(p, "fixture-key")
	if w.Code != 200 {
		t.Fatalf("response: %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, prohibited := range []string{
		"synthetic-", "private-proxy.example", "8080", "/synthetic/", "Authorization",
		"X-Machine", "X-Session", "Cookie", "route_key", "access_token", "refresh_token",
	} {
		if strings.Contains(body, prohibited) {
			t.Fatal("prohibited disclosure:", prohibited, body)
		}
	}
	var result struct {
		SchemaVersion  int                         `json:"schema_version"`
		TaskReporting  string                      `json:"task_reporting"`
		StrictCooldown bool                        `json:"strict_cooldown"`
		Accounts       []protocolAccountDiagnostic `json:"accounts"`
		Profiles       []upstream.ProtocolProfile  `json:"profiles"`
		// 身份矩阵（规格 §5）：用途行带身份/版本/归属头取值，另有独立 identities 三行。
		PurposeProfiles              []upstream.ProtocolPurposeProfile `json:"purpose_profiles"`
		Identities                   []upstream.IdentityProfile        `json:"identities"`
		DeviceIDPolicy               string                            `json:"device_id_policy"`
		InternationalIdentityUpgrade string                            `json:"international_identity_upgrade"`
		Warnings                     []string                          `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 1 || result.TaskReporting != "unchanged" || len(result.Profiles) != 2 ||
		len(result.Accounts) != 2 || len(result.Warnings) != 1 || result.StrictCooldown != pl.StrictCooldown() {
		t.Fatalf("schema mismatch: %+v", result)
	}
	for _, a := range result.Accounts {
		if a.UID == "a" && (a.Route.State != "ready" || a.Route.SlotID != "slot-1" || a.Route.Generation != 1 || a.DeviceToken.Source != "account") {
			t.Fatalf("bound route/token diagnostic: %+v", a)
		}
		if a.UID == "b" && (a.Route.State != "direct" || a.Route.SlotID != "" || a.DeviceToken.Source != "global") {
			t.Fatalf("direct route/token diagnostic: %+v", a)
		}
	}
	// ── 身份矩阵断言（规格 §5）──
	if result.DeviceIDPolicy != "per_account_stable_desktop_unified_mp_unique" ||
		result.InternationalIdentityUpgrade != "applied_global_desktop_5_8_4" {
		t.Fatalf("identity policy flags: %q / %q", result.DeviceIDPolicy, result.InternationalIdentityUpgrade)
	}
	if len(result.PurposeProfiles) != 8 {
		t.Fatalf("purpose_profiles rows = %d want 8", len(result.PurposeProfiles))
	}
	for _, row := range result.PurposeProfiles {
		if row.Identity != "workbuddy-desktop" {
			t.Fatalf("purpose row identity = %q (realm=%s purpose=%s)", row.Identity, row.Realm, row.Purpose)
		}
		wantVersion := "fixture-client" // 显式 client_version 覆盖矩阵默认
		if row.ClientVersion != wantVersion || row.IdeVersion != wantVersion {
			t.Fatalf("purpose row versions = %q/%q want %q", row.ClientVersion, row.IdeVersion, wantVersion)
		}
		isBilling := row.Purpose == "billing"
		if isBilling && (row.MachineHeader || row.SessionHeader || row.PrivateData || row.AgentIntent != "" || row.Origin != "") {
			t.Fatalf("billing row must stay header-free: %+v", row)
		}
		if !isBilling && (!row.MachineHeader || !row.SessionHeader) {
			t.Fatalf("non-billing row must keep machine/session headers: %+v", row)
		}
		if !isBilling && row.Realm == "global" {
			if row.AgentIntent != "craft" || row.AgentType != "main" || !row.PrivateData {
				t.Fatalf("global row attribution missing: %+v", row)
			}
		} else if row.AgentIntent != "" || row.AgentType != "" || row.PrivateData {
			t.Fatalf("CN row must not claim intl attribution: %+v", row)
		}
	}
	if len(result.Identities) != 3 {
		t.Fatalf("identities rows = %d want 3", len(result.Identities))
	}
	byKey := map[string]upstream.IdentityProfile{}
	for _, id := range result.Identities {
		byKey[id.Realm+"/"+id.Identity] = id
	}
	// 小程序端版本固定 2.4.0：不跟随桌面端 client_version 覆盖（零漂移）。
	mp := byKey["cn/workbuddy-mp"]
	if mp.ClientVersion != "2.4.0" || mp.IdeVersion != "2.4.0" || mp.UserAgent != "" || mp.Product != "SaaS" {
		t.Fatalf("mp identity row: %+v", mp)
	}
	cn := byKey["cn/workbuddy-desktop"]
	if !strings.Contains(cn.UserAgent, "WorkBuddy/") || strings.Contains(cn.UserAgent, "workbuddy-ai") {
		t.Fatalf("cn desktop identity UA: %q", cn.UserAgent)
	}
	if cn.Language != "zh-CN" || cn.Origin != "https://www.codebuddy.cn" {
		t.Fatalf("cn desktop identity origin/language: %+v", cn)
	}
	pl.SetStrictCooldown(false)
	p.cfg.Egress = nil
	w = diagnosticsCall(p, "fixture-key")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"not_configured"`) ||
		!strings.Contains(w.Body.String(), `"strict_cooldown":false`) {
		t.Fatal("unconfigured route/live strict cooldown not accurately reported", w.Code, w.Body)
	}
	c.DeviceToken = ""
	w = diagnosticsCall(p, "fixture-key")
	if !strings.Contains(w.Body.String(), `"device_token":{"source":"file","configured":true}`) {
		t.Fatal("file token presence must remain unknown", w.Body)
	}
	if transport.calls.Load() != 0 {
		t.Fatal("diagnostics made network requests", transport.calls.Load())
	}
}

func TestProtocolDiagnosticsEmptyCollections(t *testing.T) {
	p := New(Config{Pool: pool.New(""), Upstream: &upstream.Client{}, APIKey: "fixture-key"})
	w := diagnosticsCall(p, "fixture-key")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"accounts":[]`) ||
		!strings.Contains(w.Body.String(), `"warnings":[]`) {
		t.Fatal("empty collections must remain arrays", w.Code, w.Body)
	}
}
