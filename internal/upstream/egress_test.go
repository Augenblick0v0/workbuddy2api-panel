package upstream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func proxyFixture(t *testing.T, targets ...string) (*Client, *egress.Manager) {
	t.Helper()
	return proxyFixtureTimeout(t, 0, targets...)
}
func proxyFixtureTimeout(t *testing.T, timeout time.Duration, targets ...string) (*Client, *egress.Manager) {
	t.Helper()
	c := New()
	if timeout > 0 {
		c.HTTP.Transport.(*http.Transport).ResponseHeaderTimeout = timeout
	}
	m, err := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{
		BaseTransport: c.HTTP.Transport.(*http.Transport), AllowedCIDRs: []string{"127.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(0, func(cfg *egress.Config) error {
		for i, target := range targets {
			u, _ := url.Parse(target)
			host, port, _ := net.SplitHostPort(u.Host)
			p, _ := strconv.Atoi(port)
			id := "slot-" + strconv.Itoa(i+1)
			cfg.Slots[id] = egress.Slot{ID: id, Name: id, Enabled: true, Scheme: "http", Host: host, Port: p}
			cfg.Bindings[string(rune('A'+i))] = id
		}
		cfg.NextSlotSeq = uint64(len(targets) + 1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c.InstallEgress(m)
	t.Cleanup(m.CloseIdleConnections)
	return c, m
}

func TestProxyAccountOutboundMatrix(t *testing.T) {
	var direct atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1); w.Write([]byte(`{"code":0,"data":{}}`)) }))
	defer target.Close()
	var hits [2]atomic.Int64
	proxies := make([]*httptest.Server, 2)
	for i := range proxies {
		idx := i
		proxies[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[idx].Add(1)
			if !r.URL.IsAbs() {
				t.Error("expected forward proxy absolute URL")
			}
			if r.Header.Get("Proxy-Authorization") != "" {
				t.Error("unexpected proxy credentials")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"code":0,"data":{"accessToken":"rotated","refreshToken":"rotated-refresh","nickname":"fixture","models":[]}}`))
		}))
		defer proxies[i].Close()
	}
	c, _ := proxyFixture(t, proxies[0].URL, proxies[1].URL)
	c.ChatBaseCN, c.BillingBaseCN, c.WebBaseCN = target.URL, target.URL, target.URL
	c.ChatBaseGlobal, c.BillingBaseGlobal = target.URL, target.URL
	calls := []struct {
		name string
		run  func(*auth.Auth)
	}{
		{"refresh", func(a *auth.Auth) { c.RefreshToken(a) }},
		{"chat", func(a *auth.Auth) {
			rc, _, _, _ := c.ChatStreamContext(context.Background(), a, []byte(`{"model":"glm-5.2","messages":[]}`), "", ChatMeta{})
			if rc != nil {
				rc.Close()
			}
		}},
		{"enterprise-models", func(a *auth.Auth) { c.fetchEnterpriseModels(a) }},
		{"v3-config", func(a *auth.Auth) { c.fetchV3ConfigModelMap(a, "") }},
		{"global-models", func(a *auth.Auth) { c.globalModelsOnce(a, "/v2/models") }},
		{"global-countries", func(a *auth.Auth) { c.GlobalFetchCountries(a, false) }},
		{"global-status", func(a *auth.Auth) { c.GlobalRegisterStatus(a) }},
		{"global-region", func(a *auth.Auth) { c.GlobalSubmitRegion(a, GlobalCountry{Code: "344", IOS2: "HK"}) }},
		{"profile", func(a *auth.Auth) { c.FetchAccountProfile(a) }},
		{"billing", func(a *auth.Auth) { c.billingJSON(a, http.MethodGet, "/balance", nil) }},
		{"billing-meter", func(a *auth.Auth) { c.billingMeterJSON(a, []string{"/meter"}, http.MethodPost, nil) }},
		{"trial", func(a *auth.Auth) { c.ClaimTrial(a) }},
		{"report", func(a *auth.Auth) { c.ReportChatActivity(a, "c", "r") }},
		{"growth", func(a *auth.Auth) { c.growthJSON(a, http.MethodGet, "/growth", nil) }},
		{"tasks", func(a *auth.Auth) { c.ListTasks(a) }},
		{"tasks-mp", func(a *auth.Auth) { c.ListTasksMP(a) }},
		{"claim-mp", func(a *auth.Auth) { c.ClaimRewardMP(a, "fixture") }},
		{"claim-web", func(a *auth.Auth) { c.ClaimReward(a, "fixture") }},
		{"school", func(a *auth.Auth) { c.schoolJSON(a, http.MethodGet, "/school", nil, &map[string]any{}) }},
		{"mp-event", func(a *auth.Auth) { c.ReportMPEvent(a, map[string]any{"event": "fixture"}) }},
		{"desktop-event", func(a *auth.Auth) { c.ReportDesktopEvent(a, DesktopEvent{}) }},
		{"desktop-theme", func(a *auth.Auth) { c.SetAppearanceTheme(a, "fixture") }},
		{"web-event", func(a *auth.Auth) { c.ReportWebEvent(a, "fixture", "/", "", "") }},
		{"market", func(a *auth.Auth) { c.MarketExpertList(a, "") }},
		{"expert-chat", func(a *auth.Auth) { c.DesktopChatWithExpert(a, "fixture") }},
	}
	for _, call := range calls {
		for i, uid := range []string{"A", "B"} {
			t.Run(call.name+"/"+uid, func(t *testing.T) {
				realm := "cn"
				if strings.HasPrefix(call.name, "global-") || call.name == "trial" {
					realm = "global"
				}
				a, err := auth.Parse([]byte(`{"uid":"` + uid + `","accessToken":"fixture","refreshToken":"fixture","realm":"` + realm + `"}`))
				if err != nil {
					t.Fatal(err)
				}
				before, other := hits[i].Load(), hits[1-i].Load()
				call.run(a)
				if hits[i].Load() != before+1 || hits[1-i].Load() != other {
					t.Fatalf("routes got A=%d B=%d, wanted exactly one on %s", hits[0].Load(), hits[1].Load(), uid)
				}
			})
		}
	}
	if direct.Load() != 0 {
		t.Fatalf("direct leak: %d", direct.Load())
	}
	// Even an apparently valid bearer and user-id do not select a route.
	req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	req.Header.Set("Authorization", "Bearer fixture")
	req.Header.Set("X-User-Id", "A")
	if _, err := c.HTTP.Do(req); err == nil {
		t.Fatal("naked Do accepted")
	}
	if c.HTTP.Timeout != 120*time.Second || c.ChatHTTP.Timeout != 0 || c.PublicHTTP.Transport == c.HTTP.Transport {
		t.Fatal("client isolation/timeout regression")
	}
}

func TestProxyFixedRouteChecksGeneration(t *testing.T) {
	var calls atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(`{"code":0,"data":{}}`)) }))
	defer proxy.Close()
	c, m := proxyFixture(t, proxy.URL)
	h, err := m.ResolveSlot("slot-1")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	c.BillingBaseCN = "http://upstream.invalid"
	pinned := c.ForRoute(h)
	// B is unbound/direct, yet OAuth maintenance must use the caller's handle.
	a := &auth.Auth{UID: "B", AccessToken: "fixture"}
	if _, err := pinned.billingJSON(a, http.MethodGet, "/fixture", nil); err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(m.Snapshot().Revision, func(cfg *egress.Config) error {
		s := cfg.Slots["slot-1"]
		s.Password = "changed"
		cfg.Slots[s.ID] = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pinned.billingJSON(a, http.MethodGet, "/fixture", nil)
	var ee *egress.EgressError
	if !errors.As(err, &ee) || ee.Code != "oauth_proxy_changed" || calls.Load() != 1 {
		t.Fatalf("changed route continued: %v calls=%d", err, calls.Load())
	}
}

func TestProxyRefreshReplacementBarrier(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-resume
		w.Write([]byte(`{"code":0,"data":{"accessToken":"stale-refresh","refreshToken":"stale-refresh-rt"}}`))
	}))
	defer server.Close()
	a := &auth.Auth{UID: "A", AccessToken: "old", RefreshToken: "old-rt", FilePath: filepath.Join(t.TempDir(), "auth.json")}
	c := New()
	c.ChatBaseCN = server.URL
	done := make(chan error, 1)
	go func() { done <- c.RefreshToken(a) }()
	<-entered
	if err := a.ReplaceCredentials(&auth.Auth{UID: "A", AccessToken: "new-login", RefreshToken: "new-login-rt"}); err != nil {
		t.Fatal(err)
	}
	close(resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if a.AccessTokenValue() != "new-login" {
		t.Fatal("stale refresh overwrote OAuth")
	}
}

func TestProxyBillingNeverReplays(t *testing.T) {
	for _, mode := range []string{"407", "cut", "body-cut", "500"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int64
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch mode {
				case "407":
					w.WriteHeader(407)
				case "body-cut":
					w.Header().Set("Content-Length", "10000")
					w.Write([]byte(`{"code":`))
				case "500":
					w.WriteHeader(500)
					w.Write([]byte(`{"code":10000,"msg":"failure"}`))
				case "cut":
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
				}
			}))
			defer proxy.Close()
			c, _ := proxyFixture(t, proxy.URL)
			err := c.DailyCheckin(&auth.Auth{UID: "A", AccessToken: "fixture"})
			if err == nil || calls.Load() != 1 {
				t.Fatalf("replayed: %v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestProxySSEHotUpdate(t *testing.T) {
	firstStarted, finishFirst := make(chan struct{}), make(chan struct{})
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: first\n\n"))
		w.(http.Flusher).Flush()
		close(firstStarted)
		<-finishFirst
		w.Write([]byte("data: old-finished\n\n"))
	}))
	defer first.Close()
	var newCalls atomic.Int64
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newCalls.Add(1)
		w.Write([]byte("data: new\n\n"))
	}))
	defer second.Close()
	c, m := proxyFixture(t, first.URL)
	c.ChatBaseCN = "http://upstream.invalid"
	a := &auth.Auth{UID: "A", AccessToken: "fixture"}
	rc, _, _, err := c.ChatStream(a, []byte(`{"model":"glm-5.2","messages":[]}`), "", ChatMeta{})
	if err != nil {
		t.Fatal(err)
	}
	<-firstStarted
	u, _ := url.Parse(second.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	_, err = m.Update(m.Snapshot().Revision, func(cfg *egress.Config) error { s := cfg.Slots["slot-1"]; s.Port = p; cfg.Slots[s.ID] = s; return nil })
	if err != nil {
		t.Fatal(err)
	}
	next, _, _, err := c.ChatStream(a, []byte(`{"model":"glm-5.2","messages":[]}`), "", ChatMeta{})
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
	close(finishFirst)
	raw, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !strings.Contains(string(raw), "old-finished") || newCalls.Load() != 1 {
		t.Fatalf("generation transition interrupted old stream: %q %v calls=%d", raw, err, newCalls.Load())
	}
}

func TestProxyHeaderTimeoutEveryGeneration(t *testing.T) {
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	firstSeen, secondSeen := make(chan struct{}), make(chan struct{})
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(firstSeen); <-releaseFirst }))
	defer first.Close()
	defer close(releaseFirst)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(secondSeen); <-releaseSecond }))
	defer second.Close()
	defer close(releaseSecond)
	c, m := proxyFixtureTimeout(t, 40*time.Millisecond, first.URL)
	c.ChatBaseCN = "http://upstream.invalid"
	a := &auth.Auth{UID: "A", AccessToken: "fixture"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, _, _, err := c.ChatStreamContext(ctx, a, []byte(`{"model":"glm-5.2","messages":[]}`), "", ChatMeta{})
	var ee *egress.EgressError
	if !errors.As(err, &ee) || ee.Code != "upstream_timeout" || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("initial header timeout lost: %v duration=%v", err, time.Since(start))
	}
	<-firstSeen
	u, _ := url.Parse(second.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	_, err = m.Update(m.Snapshot().Revision, func(cfg *egress.Config) error { s := cfg.Slots["slot-1"]; s.Port = p; cfg.Slots[s.ID] = s; return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	req, _ := http.NewRequestWithContext(ctx2, http.MethodGet, "http://upstream.invalid/rpc", nil)
	start = time.Now()
	_, err = c.doJSON(req, a)
	if !errors.As(err, &ee) || ee.Code != "upstream_timeout" || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("new generation/RPC header timeout lost: %v duration=%v", err, time.Since(start))
	}
	<-secondSeen
}

func TestProxyPublicCatalogAndRedirectIsolation(t *testing.T) {
	var direct, proxied atomic.Int64
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("public catalog received account credential")
		}
		w.Write([]byte(`{"zai":{"models":{"fixture":{"limit":{"context":8192}}}}}`))
	}))
	defer public.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		w.Header().Set("Location", public.URL)
		w.WriteHeader(302)
	}))
	defer proxy.Close()
	c, _ := proxyFixture(t, proxy.URL)
	f := &modelsDevFetcher{}
	f.fetchDoc(c.PublicClient(), public.URL)
	if direct.Load() != 1 || proxied.Load() != 0 {
		t.Fatal("public catalog used account transport")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://upstream.invalid", nil)
	req.Header.Set("Authorization", "Bearer fixture")
	resp, err := c.sendAccount(req, &auth.Auth{UID: "A", AccessToken: "fixture"}, false)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || direct.Load() != 1 || proxied.Load() != 1 {
		t.Fatal("redirect rerouted account credential")
	}
}
