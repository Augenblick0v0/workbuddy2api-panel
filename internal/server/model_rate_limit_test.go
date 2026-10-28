package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func Test6000ModelLimitPolicy(t *testing.T) {
	for _, hint := range []string{"reset", "none", "header"} {
		t.Run(hint, func(t *testing.T) {
			p := testPoolWith(&auth.Auth{UID: "u1"})
			h := NewHandler(Config{Pool: p, SoftCooldown: time.Minute})
			msg := "您的使用量已超出频率限制，您也可以切换其他模型继续使用。"
			target := time.Now().Add(time.Minute)
			if hint == "reset" {
				target = time.Now().Add(5 * time.Minute)
				msg = "您的使用量已超出频率限制，将在 " + target.In(upstream.SoftRateResetLoc()).Format("2006-01-02 15:04:05") + " UTC+8 重置，您也可以切换其他模型继续使用。"
			}
			body := fmt.Sprintf(`{"code":6000,"msg":%q}`, msg)
			var ue *upstream.Error
			if hint == "header" {
				ue = &upstream.Error{RetryAfter: 30 * time.Second}
				target = time.Now().Add(30 * time.Second)
			}
			h.applyErrorPolicy("u1", upstream.ErrSoftRate, body, "kimi-k3.1-pro", ue)
			s, _ := p.Status("u1")
			if s.Cooling || s.BreakerFails != 0 || s.ConsecutiveFails != 0 {
				t.Fatalf("account penalty: %+v", s)
			}
			if len(s.RateLimitedModels) != 1 || s.RateLimitedModels[0].Kind != "rate_limit" {
				t.Fatalf("missing ledger: %+v", s)
			}
			if d := s.RateLimitedModels[0].Until.Sub(target); d < -2*time.Second || d > 2*time.Second {
				t.Fatalf("deadline=%v target=%v", s.RateLimitedModels[0].Until, target)
			}
			if p.PickByUIDForModel("u1", "kimi-k3.1-pro") != nil {
				t.Fatal("frozen model selected")
			}
			if p.PickByUIDForModel("u1", "deepseek-v4.1-flash") == nil {
				t.Fatal("other model blocked")
			}
		})
	}
}

func TestModelLimitPreservesAccountRestriction(t *testing.T) {
	p := testPoolWith(&auth.Auth{UID: "u1"})
	p.Cooldown("u1", pool.CoolHard, time.Hour, "real credit restriction")
	h := NewHandler(Config{Pool: p})
	h.applyErrorPolicy("u1", upstream.ErrSoftRate, `{"code":6000,"msg":"切换其他模型"}`, "kimi-k3.1-pro", nil)
	s, _ := p.Status("u1")
	if !s.Cooling || s.Reason != "real credit restriction" || p.PickByUIDForModel("u1", "deepseek-v4.1-flash") != nil {
		t.Fatalf("lost account restriction: %+v", s)
	}
}

func Test6000HTTPIsolationAndPersistence(t *testing.T) {
	path := t.TempDir() + "/state.json"
	p := pool.New(path)
	defer p.Close()
	p.Add(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999})
	p.SetCredits("u1", 1000, 0)
	calls := 0
	reset := time.Now().Add(15 * time.Minute).In(upstream.SoftRateResetLoc()).Format("2006-01-02 15:04:05")
	up := newFakeUpstream(t, func(a string) (int, string, bool) {
		calls++
		if calls == 1 {
			return 429, `{"code":6000,"msg":"将在 ` + reset + ` UTC+8 重置，您也可以切换其他模型继续使用。"}`, false
		}
		return 200, sseOK, true
	})
	h := NewHandler(Config{Pool: p, Upstream: up})
	request := func(model string) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"cn:`+model+`","messages":[]}`)))
		return r
	}
	request("kimi-k3.1-pro")
	if calls != 1 {
		t.Fatalf("calls=%d want1", calls)
	}
	if r := request("deepseek-v4.1-flash"); r.Code != 200 {
		t.Fatalf("other model status=%d %s", r.Code, r.Body)
	}
	if r := request("kimi-k3.1-pro"); r.Code != 400 || calls != 2 {
		t.Fatalf("frozen model reached upstream: status=%d calls=%d body=%s", r.Code, calls, r.Body)
	}
	p.Flush()
	restored := pool.New(path)
	defer restored.Close()
	restored.Add(&auth.Auth{UID: "u1"})
	if restored.PickByUIDForModel("u1", "kimi-k3.1-pro") != nil || restored.PickByUIDForModel("u1", "deepseek-v4.1-flash") == nil {
		t.Fatal("model isolation lost on restart")
	}
}

func Test6000AmbiguousRemainsAccountScoped(t *testing.T) {
	p := testPoolWith(&auth.Auth{UID: "u1"})
	h := NewHandler(Config{Pool: p})
	body := `{"code":6000,"msg":"generic account rate limit"}`
	h.applyErrorPolicy("u1", upstream.Classify(429, body), body, "kimi-k3.1-pro", nil)
	s, _ := p.Status("u1")
	if !s.Cooling || len(s.RateLimitedModels) != 0 {
		t.Fatalf("ambiguous limit escaped account policy: %+v", s)
	}
}

func Test6000SSEModelLimitIsNotSuccess(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%v/nested=%v", stream, nested), func(t *testing.T) {
				p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999})
				payload := `{"code":6000,"msg":"切换其他模型"}`
				if nested {
					payload = `{"error":{"code":6000,"message":"切换其他模型"}}`
				}
				calls := 0
				up := newFakeUpstream(t, func(a string) (int, string, bool) {
					calls++
					return 200, `data: {"choices":[{"delta":{"role":"assistant","content":"prefix"}}]}` + "\n\n" + "data: " + payload + "\n\ndata: [DONE]\n\n", true
				})
				transport := up.HTTP.Transport
				up.HTTP.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
					response, err := transport.RoundTrip(req)
					if response != nil {
						response.Header.Set("Retry-After", "30")
					}
					return response, err
				})
				h := NewHandler(Config{Pool: p, Upstream: up})
				r := httptest.NewRecorder()
				h.ServeHTTP(r, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(fmt.Sprintf(`{"model":"cn:kimi-k3.1-pro","stream":%v,"messages":[]}`, stream))))
				s, _ := p.Status("u1")
				if calls != 1 || s.SuccessCount != 0 || s.Cooling || len(s.RateLimitedModels) != 1 || s.BreakerFails != 0 {
					t.Fatalf("calls=%d status=%d account=%+v", calls, r.Code, s)
				}
				if d := time.Until(s.RateLimitedModels[0].Until); d < 28*time.Second || d > 30*time.Second {
					t.Fatalf("lost HTTP retry hint: %v", d)
				}
				if !strings.Contains(r.Body.String(), "6000") {
					t.Fatalf("lost upstream error: %s", r.Body)
				}
				if !stream && r.Code != 429 {
					t.Fatalf("aggregate status=%d want429", r.Code)
				}
			})
		}
	}
}
