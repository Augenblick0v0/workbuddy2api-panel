package panel

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

type importOfflineTransport struct{ calls int }

func (r *importOfflineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: 400, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":400,"msg":"synthetic offline maintenance"}`))}, nil
}

func newImportPanel(t *testing.T) (*Panel, *importOfflineTransport) {
	t.Helper()
	dir := t.TempDir()
	transport := &importOfflineTransport{}
	client := upstream.New()
	client.HTTP.Transport = transport
	pl := pool.New("")
	t.Cleanup(pl.Close)
	return New(Config{AuthDir: dir, Pool: pl, Upstream: client, APIKey: "key"}), transport
}

func importJSON(t *testing.T, p *Panel, raw string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	f, err := mw.CreateFormFile("file", "fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://panel.test/panel/api/import/cockpit", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Authorization", "Bearer key")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

const nestedImportFixture = `{"account":{"enterpriseId":"fixture-enterprise","nickname":"fixture nickname","uid":"fixture-import-uid"},"auth":{"accessToken":"synthetic-access","domain":"api.workbuddy.ai","expiresAt":2000000000,"realm":"global","refreshToken":"synthetic-refresh"}}`

func TestImportNestedWorkBuddyObject(t *testing.T) {
	p, _ := newImportPanel(t)
	w := importJSON(t, p, nestedImportFixture)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"imported":1`) {
		t.Fatalf("nested object import: HTTP %d %s", w.Code, w.Body.String())
	}
	a := p.cfg.Pool.AuthByUID("fixture-import-uid")
	if a == nil {
		t.Fatal("imported account missing from pool")
	}
	raw, err := os.ReadFile(filepath.Join(p.cfg.AuthDir, "workbuddy-fixture-import-uid.json"))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := auth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if saved.EnterpriseID != "fixture-enterprise" || saved.Realm() != "global" || saved.ExpiresAt != 2000000000 || saved.AccessTokenValue() != "synthetic-access" || saved.RefreshTokenValue() != "synthetic-refresh" {
		t.Fatal("nested fields were lost or expiry units changed")
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	t.Logf("IMPORT_RESULT HTTP=%d total=%.0f imported=%.0f skipped=%.0f", w.Code, result["total"], result["imported"], result["skipped"])
}

func TestImportCompatibleFormats(t *testing.T) {
	legacy := `{"uid":"fixture-import-uid","email":"fixture@example.invalid","access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_at":2000000000000,"domain":"fixture.invalid"}`
	for name, raw := range map[string]string{
		"cockpit_array_ms":       "[" + legacy + "]",
		"cockpit_object_seconds": strings.Replace(legacy, "2000000000000", "2000000000", 1),
		"nested_array":           "[" + nestedImportFixture + "]",
		"nested_ms":              strings.Replace(nestedImportFixture, "2000000000", "2000000000000", 1),
		"utf8_bom":               "\xef\xbb\xbf" + nestedImportFixture,
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := newImportPanel(t)
			w := importJSON(t, p, raw)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"imported":1`) {
				t.Fatalf("HTTP %d %s", w.Code, w.Body)
			}
			a := p.cfg.Pool.AuthByUID("fixture-import-uid")
			if a == nil || a.ExpiresAt != 2000000000 {
				t.Fatal("expiry normalization failed")
			}
			if strings.Contains(name, "cockpit") && a.Realm() != "cn" {
				t.Fatal("CN became global")
			}
		})
	}
}

func TestImportRejectMalformedWithoutWrites(t *testing.T) {
	for _, raw := range []string{"", "{", "null", "42", `"x"`, "[]", "{}", "[null]", `{"auth":{},"account":null}`, `{"auth":null,"account":{}}`, "[" + nestedImportFixture + ",null]", `{"auth":{"accessToken":4},"account":{}}`} {
		p, transport := newImportPanel(t)
		w := importJSON(t, p, raw)
		if w.Code != 400 {
			t.Errorf("invalid input accepted: HTTP %d", w.Code)
		}
		files, err := os.ReadDir(p.cfg.AuthDir)
		if err != nil || len(files) != 0 || transport.calls != 0 {
			t.Fatal("invalid document caused writes or upstream calls")
		}
	}
}

func TestImportRejectUIDAndMissingFields(t *testing.T) {
	for _, raw := range []string{strings.Replace(nestedImportFixture, "fixture-import-uid", "../bad", 1), strings.Replace(nestedImportFixture, "synthetic-refresh", "", 1)} {
		p, transport := newImportPanel(t)
		w := importJSON(t, p, raw)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"skipped":1`) || !strings.Contains(w.Body.String(), `"imported":0`) {
			t.Fatalf("HTTP %d %s", w.Code, w.Body)
		}
		files, _ := os.ReadDir(p.cfg.AuthDir)
		if len(files) != 0 || transport.calls != 0 {
			t.Fatal("invalid account caused writes or sends")
		}
	}
}

func TestImportExistingPreservesStateAndBinding(t *testing.T) {
	p, transport := newImportPanel(t)
	a := &auth.Auth{UID: "fixture-import-uid", Domain: "api.workbuddy.ai", AccessToken: "old-access", RefreshToken: "old-refresh", DeviceToken: "existing-device-token", EnterpriseID: "existing-enterprise", Nickname: "existing nickname", FilePath: filepath.Join(p.cfg.AuthDir, "workbuddy-fixture-import-uid.json")}
	if err := a.SaveAtomic(); err != nil {
		t.Fatal(err)
	}
	p.cfg.Pool.Add(a)
	p.cfg.Pool.Disable(a.UID, "fixture-disabled")
	beforeState, _ := p.cfg.Pool.Status(a.UID)
	m, err := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.CloseIdleConnections)
	_, err = m.Update(0, func(c *egress.Config) error {
		c.Slots["slot-1"] = egress.Slot{ID: "slot-1", Name: "fixture", Enabled: true, Scheme: "http", Host: "proxy.invalid", Port: 8080}
		c.Bindings[a.UID] = "slot-1"
		c.NextSlotSeq = 2
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p.cfg.Egress = m
	beforeBinding := m.Snapshot()
	for i := 0; i < 2; i++ {
		w := importJSON(t, p, nestedImportFixture)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"imported":1`) {
			t.Fatalf("HTTP %d %s", w.Code, w.Body)
		}
	}
	afterState, _ := p.cfg.Pool.Status(a.UID)
	if !reflect.DeepEqual(beforeBinding, m.Snapshot()) || !reflect.DeepEqual(beforeState, afterState) {
		t.Fatal("import changed route or account state")
	}
	if p.cfg.Pool.AuthByUID(a.UID) != a || a.DeviceToken != "existing-device-token" || a.EnterpriseID != "existing-enterprise" || a.Nickname != "existing nickname" || a.AccessTokenValue() != "synthetic-access" || a.CredentialEpoch != 2 {
		t.Fatal("replacement lost persistent identity or refresh concurrency protection")
	}
	if transport.calls != 0 {
		t.Fatal("existing account import triggered maintenance")
	}
}

func TestImportCredentialWriteFailurePreservesPool(t *testing.T) {
	p, transport := newImportPanel(t)
	blocked := filepath.Join(p.cfg.AuthDir, "blocked")
	if err := os.WriteFile(blocked, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &auth.Auth{UID: "fixture-import-uid", AccessToken: "old-access", RefreshToken: "old-refresh", FilePath: filepath.Join(blocked, "no.json")}
	p.cfg.Pool.Add(a)
	w := importJSON(t, p, nestedImportFixture)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"skipped":1`) || a.AccessTokenValue() != "old-access" || a.CredentialEpoch != 0 || transport.calls != 0 {
		t.Fatal("failed write replaced credentials or sent maintenance")
	}
}

func TestImportNonMultipart(t *testing.T) {
	p, _ := newImportPanel(t)
	r := httptest.NewRequest("POST", "http://panel.test/panel/api/import/cockpit", strings.NewReader("file=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer key")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestImportSanitizedAttachment(t *testing.T) {
	raw, err := os.ReadFile("testdata/workbuddy_nested_sanitized.json")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := newImportPanel(t)
	w := importJSON(t, p, string(raw))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"imported":1`) {
		t.Fatalf("HTTP %d %s", w.Code, w.Body)
	}
	expected, err := auth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	a := p.cfg.Pool.AuthByUID(expected.UID)
	expiry := expected.ExpiresAt
	if expiry >= 100000000000 {
		expiry /= 1000
	}
	if a == nil || a.ExpiresAt != expiry || a.Realm() != expected.Realm() || a.EnterpriseID != expected.EnterpriseID {
		t.Fatal("attachment schema fields changed")
	}
}

func TestImportUIHint(t *testing.T) {
	p, _ := newImportPanel(t)
	r := httptest.NewRecorder()
	p.ServeHTTP(r, httptest.NewRequest("GET", "http://panel.test/panel/", nil))
	if !strings.Contains(r.Body.String(), "支持单账号 account/auth 对象及账号数组") || strings.Contains(r.Body.String(), "文件需为账号数组格式") {
		t.Fatal("import hint still requires an array")
	}
}

func TestImportPreservesStoredGlobalWhenRoutingDisabled(t *testing.T) {
	before := auth.GlobalEnabled()
	auth.SetGlobalEnabled(false)
	defer auth.SetGlobalEnabled(before)
	p, _ := newImportPanel(t)
	raw := strings.Replace(nestedImportFixture, `"domain":"api.workbuddy.ai"`, `"domain":""`, 1)
	w := importJSON(t, p, raw)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"imported":1`) {
		t.Fatalf("HTTP %d %s", w.Code, w.Body)
	}
	a := p.cfg.Pool.AuthByUID("fixture-import-uid")
	if a == nil || a.RealmStored() != "global" || a.Realm() != "cn" {
		t.Fatal("runtime routing switch polluted persisted realm")
	}
	saved, err := os.ReadFile(a.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := auth.Parse(saved)
	if err != nil || parsed.RealmStored() != "global" {
		t.Fatal("stored global realm was lost")
	}
	auth.SetGlobalEnabled(true)
	if parsed.Realm() != "global" {
		t.Fatal("reenabling global failed to restore account routing")
	}
}
