package panel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

func proxyPanel(t *testing.T, key string) *Panel {
	t.Helper()
	m, err := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.New("")
	for _, uid := range []string{"u1", "u2", "u3"} {
		pl.Add(&auth.Auth{UID: uid})
	}
	return New(Config{Pool: pl, Egress: m, APIKey: key})
}

func proxyCall(t *testing.T, p *Panel, method, path, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://panel.test"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer key")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestSOCKSManagementAndCredentialLimits(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			p := proxyPanel(t, "key")
			body := `{"revision":0,"scheme":"` + scheme + `","host":"proxy.invalid","port":1080,"username":"fixture","password":"synthetic-secret"}`
			w := proxyCall(t, p, "POST", "/panel/api/proxies", body, "")
			if w.Code != 201 {
				t.Fatalf("SOCKS create: %d %s", w.Code, w.Body)
			}
			w = proxyCall(t, p, "GET", "/panel/api/proxies", "", "")
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"scheme":"`+scheme+`"`) || strings.Contains(w.Body.String(), "synthetic-secret") {
				t.Fatal("SOCKS list disclosure or scheme mismatch", w.Body)
			}
			long := strings.Repeat("x", 256)
			w = proxyCall(t, p, "PATCH", "/panel/api/proxies/slot-1", `{"revision":1,"password":"`+long+`"}`, "")
			if w.Code != 400 {
				t.Fatalf("SOCKS octet limit ignored: %d", w.Code)
			}
			w = proxyCall(t, p, "PATCH", "/panel/api/proxies/slot-1", `{"revision":1,"username":""}`, "")
			if w.Code != 400 {
				t.Fatalf("password-only SOCKS accepted: %d", w.Code)
			}
		})
	}
}

func TestProxyAdminBoundary(t *testing.T) {
	p := proxyPanel(t, "")
	w := proxyCall(t, p, "GET", "/panel/api/proxies", "", "")
	if w.Code != 503 {
		t.Fatalf("empty key: %d %s", w.Code, w.Body)
	}
	p = proxyPanel(t, "key")
	w = proxyCall(t, p, "POST", "/panel/api/proxies", `{"revision":0,"name":"A","scheme":"http","host":"proxy.example","port":8080}`, "https://evil.test")
	if w.Code != 403 {
		t.Fatalf("cross origin: %d %s", w.Code, w.Body)
	}
	r := httptest.NewRequest("GET", "/panel/api/proxies", nil)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("missing bearer: %d", w.Code)
	}
}

func TestProxyManagementLifecycle(t *testing.T) {
	p := proxyPanel(t, "key")
	pass := "s:e/cret@"
	body := `{"revision":0,"operation_id":"create-a","name":"A","scheme":"http","host":"proxy.example","port":8080,"username":"user","password":"` + pass + `"}`
	w := proxyCall(t, p, "POST", "/panel/api/proxies", body, "http://panel.test")
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var created struct {
		ID       string `json:"id"`
		Revision uint64 `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID != "slot-1" || created.Revision != 1 {
		t.Fatalf("create response %s", w.Body)
	}
	first := append([]byte(nil), w.Body.Bytes()...)
	w = proxyCall(t, p, "POST", "/panel/api/proxies", body, "")
	if w.Code != 201 || !bytes.Equal(first, w.Body.Bytes()) {
		t.Fatalf("idempotency %d %s", w.Code, w.Body)
	}
	w = proxyCall(t, p, "GET", "/panel/api/proxies", "", "")
	for _, secret := range []string{pass, url.QueryEscape(pass), base64.StdEncoding.EncodeToString([]byte("user:" + pass))} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("secret leaked: %s", w.Body)
		}
	}
	w = proxyCall(t, p, "PUT", "/panel/api/accounts/u1/proxy", `{"revision":1,"slot_id":"slot-1"}`, "")
	if w.Code != 200 {
		t.Fatalf("bind: %d %s", w.Code, w.Body)
	}
	w = proxyCall(t, p, "PATCH", "/panel/api/proxies/slot-1", `{"revision":1,"name":"stale"}`, "")
	if w.Code != 409 {
		t.Fatalf("CAS: %d %s", w.Code, w.Body)
	}
	w = proxyCall(t, p, "DELETE", "/panel/api/proxies/slot-1", `{"revision":2}`, "")
	if w.Code != 409 {
		t.Fatalf("delete bound: %d %s", w.Code, w.Body)
	}
	w = proxyCall(t, p, "PATCH", "/panel/api/proxies/slot-1", `{"revision":2,"name":"renamed"}`, "")
	if w.Code != 200 || p.cfg.Egress.Snapshot().Slots["slot-1"].Password != pass {
		t.Fatalf("password preserve: %d %s", w.Code, w.Body)
	}
	w = proxyCall(t, p, "PATCH", "/panel/api/proxies/slot-1", `{"revision":3,"clear_password":true,"enabled":false}`, "")
	if w.Code != 200 {
		t.Fatalf("patch: %d %s", w.Code, w.Body)
	}
	s := p.cfg.Egress.Snapshot()
	if s.Slots["slot-1"].Password != "" || s.Bindings["u1"] != "slot-1" || p.cfg.Egress.Available("u1") {
		t.Fatal("disable must retain binding and block")
	}
}

func TestProxyAssignmentPreservesExplicitDirect(t *testing.T) {
	p := proxyPanel(t, "key")
	w := proxyCall(t, p, "POST", "/panel/api/proxies", `{"revision":0,"name":"A","scheme":"http","host":"proxy.example","port":8080}`, "")
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	w = proxyCall(t, p, "PUT", "/panel/api/accounts/u1/proxy", `{"revision":1,"slot_id":""}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	p.cfg.Pool.Pause("u3")
	w = proxyCall(t, p, "POST", "/panel/api/proxies/assign", `{"preview":true,"expected_revision":2}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var v struct {
		Assignments map[string]string `json:"assignments"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Assignments) != 1 || v.Assignments["u2"] != "slot-1" {
		t.Fatalf("preview %s", w.Body)
	}
	w = proxyCall(t, p, "POST", "/panel/api/proxies/assign", `{"expected_revision":2,"operation_id":"assign-a","assignments":{"u2":"slot-1"}}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	s := p.cfg.Egress.Snapshot()
	if val, exists := s.Bindings["u1"]; !exists || val != "" {
		t.Fatal("explicit direct lost")
	}
	if s.Bindings["u2"] != "slot-1" {
		t.Fatal("assignment not persisted")
	}
	if _, exists := s.Bindings["u3"]; exists {
		t.Fatal("paused assigned")
	}
}

func TestProxyConcurrentIdempotencyRestartAndOrphans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.json")
	m, err := egress.Open(path, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.New("")
	pl.Add(&auth.Auth{UID: "keep"})
	p := New(Config{Pool: pl, Egress: m, APIKey: "key"})
	body := `{"revision":0,"operation_id":"one","name":"A","scheme":"http","host":"proxy.example","port":8080}`
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- proxyCall(t, p, "POST", "/panel/api/proxies", body, "").Code }()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 201 {
			t.Fatalf("concurrent retry %d", code)
		}
	}
	reopened, err := egress.Open(path, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	p = New(Config{Pool: pl, Egress: reopened, APIKey: "key"})
	w := proxyCall(t, p, "POST", "/panel/api/proxies", body, "")
	if w.Code != 201 || len(reopened.Snapshot().Slots) != 1 {
		t.Fatalf("restart replay %d %s", w.Code, w.Body)
	}
	w = proxyCall(t, p, "PUT", "/panel/api/accounts/keep/proxy", `{"revision":1,"slot_id":"slot-1"}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	// Credential removal must retain its durable binding; cleanup is explicit.
	pl.Remove("keep")
	w = proxyCall(t, p, "GET", "/panel/api/proxies", "", "")
	if !strings.Contains(w.Body.String(), `"orphan":true`) {
		t.Fatal(w.Body)
	}
	w = proxyCall(t, p, "DELETE", "/panel/api/accounts/keep/proxy", `{"revision":2,"confirm":true}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = proxyCall(t, p, "DELETE", "/panel/api/proxies/slot-1", `{"revision":3}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = proxyCall(t, p, "POST", "/panel/api/proxies", `{"revision":4,"scheme":"http","host":"proxy.example","port":8080}`, "")
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"id":"slot-2"`) {
		t.Fatal("ID reused", w.Code, w.Body)
	}
}
