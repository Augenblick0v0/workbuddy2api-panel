package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	"github.com/linguo2625469/workbuddy2api-panel/internal/server"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// Explicit opt-in interactive fixture. No real account or internet upstream is
// used; all synthetic traffic terminates in the counting local proxy handlers.
func TestProxyUIFixtureServe(t *testing.T) {
	if os.Getenv("WBPROXY_UI_FIXTURE") != "1" {
		t.Skip("interactive local fixture opt-in")
	}
	var countA, countB, direct atomic.Int64
	var states atomic.Int64
	proxy := func(ip string, count *atomic.Int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			if r.Method == http.MethodConnect {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			var data any = map[string]any{}
			switch {
			case strings.Contains(r.URL.Path, "fixture/state"):
				data = map[string]any{"state": fmt.Sprintf("fixture-state-%d", states.Add(1)), "authUrl": "https://example.invalid/fixture-authorization"}
			case strings.Contains(r.URL.Path, "fixture/token"):
				data = map[string]any{"accessToken": "synthetic-ui-access", "refreshToken": "synthetic-ui-refresh", "expiresIn": 7200}
			case strings.Contains(r.URL.Path, "fixture/account"):
				data = map[string]any{"uid": "oauth-fixture", "nickname": "OAuth 合成账号", "enterpriseId": "fixture-enterprise"}
			case r.URL.Path == "/ip":
				_ = json.NewEncoder(w).Encode(map[string]string{"ip": ip})
				return
			case strings.Contains(r.URL.Path, "chat/completions"):
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"fixture\",\"choices\":[{\"delta\":{\"content\":\"fixture ok\"}}]}\n\ndata: [DONE]\n\n")
				return
			case strings.Contains(r.URL.Path, "get-enterprise-user-usage"):
				data = map[string]any{"limitNum": 1000, "credit": 1}
			case strings.Contains(r.URL.Path, "register"):
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": data})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": data})
		}))
	}
	a, b := proxy("203.0.113.10", &countA), proxy("203.0.113.20", &countB)
	defer a.Close()
	defer b.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1); w.WriteHeader(500) }))
	defer target.Close()
	dir := t.TempDir()
	base := upstream.New()
	manager, err := egress.Open(filepath.Join(dir, "data", "proxies.json"), egress.Options{
		BaseTransport: base.HTTP.Transport.(*http.Transport), AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.fixture/ip", ProbeHTTPSURL: "https://probe.fixture/ip",
	})
	if err != nil {
		t.Fatal(err)
	}
	addSlot := func(c *egress.Config, id, name, endpoint string) {
		u, _ := url.Parse(endpoint)
		port, _ := strconv.Atoi(u.Port())
		c.Slots[id] = egress.Slot{ID: id, Name: name, Enabled: true, Scheme: "http", Host: u.Hostname(), Port: port}
	}
	_, err = manager.Update(0, func(c *egress.Config) error {
		addSlot(c, "slot-1", "本地 A 出口", a.URL)
		addSlot(c, "slot-2", "本地 B 出口", b.URL)
		c.NextSlotSeq = 3
		c.Bindings["fixture-cn-1"] = "slot-1"
		c.Bindings["fixture-direct"] = ""
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if install, ok := any(base).(interface{ InstallEgress(*egress.Manager) }); ok {
		install.InstallEgress(manager)
	} else {
		t.Fatal("outbound integration pending")
	}
	base.ChatBaseCN = target.URL
	base.BillingBaseCN = target.URL
	base.WebBaseCN = target.URL
	pl := pool.New("")
	defer pl.Close()
	for i, uid := range []string{"fixture-cn-1", "fixture-cn-2", "fixture-direct"} {
		pl.Add(&auth.Auth{UID: uid, Nickname: []string{"固定 A · 合成账号", "待分配 · 合成账号", "显式直连 · 合成账号"}[i], AccessToken: "synthetic", RefreshToken: "synthetic-refresh", ExpiresAt: time.Now().Add(4 * time.Hour).Unix()})
		pl.SetCredits(uid, int64(250+i*100), 1000)
	}
	p := New(Config{Pool: pl, Upstream: base, Egress: manager, APIKey: "fixture-key", AuthDir: filepath.Join(dir, "auths"), Version: "1.13.0-panel · proxy fixture",
		LoginEndpoints: func(string) (string, string, string, string) {
			return target.URL + "/fixture/state", target.URL + "/fixture/token?state=", target.URL + "/fixture/account?state=", target.URL
		},
	})
	handler := server.NewHandler(server.Config{Pool: pl, Upstream: base, Panel: p, APIKey: "fixture-key"})
	mux := http.NewServeMux()
	stop := make(chan struct{})
	var stopOnce sync.Once
	mux.HandleFunc("POST /fixture/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-key" {
			w.WriteHeader(401)
			return
		}
		stopOnce.Do(func() { close(stop) })
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /fixture/counts", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"proxy_a": countA.Load(), "proxy_b": countB.Load(), "direct": direct.Load(), "proxy_a_address": a.URL, "proxy_b_address": b.URL})
	})
	mux.Handle("/", handler)
	ln, err := net.Listen("tcp", "127.0.0.1:17863")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	t.Logf("UI FIXTURE http://127.0.0.1:17863/panel/ key=fixture-key A=%s B=%s temp=%s", a.URL, b.URL, dir)
	select {
	case <-stop:
	case <-time.After(45 * time.Minute):
	}
	_ = srv.Shutdown(context.Background())
	if direct.Load() != 0 {
		t.Fatalf("fixture leaked %d direct requests", direct.Load())
	}
}
