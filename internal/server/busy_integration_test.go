package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

const busyBody = `{"code":6021,"msg":"queue.full.title"}`
const busyFrame = "data: {\"error\":{\"code\":6021,\"message\":\"queue.full.title\"}}\n\n"

func fastBusy(h *Handler, retries int) {
	p := defaultBusyPolicy(retries, h.cfg.MaxRotate)
	p.BaseDelay = time.Millisecond
	p.JitterMax = 0
	p.Budget = time.Second
	h.busyPolicyOverride = &p
}
func busyRequest(h *Handler, stream bool) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(fmt.Sprintf(`{"model":"cn:glm-5.2","stream":%v,"messages":[{"role":"user","content":"hi"}]}`, stream))))
	return rec
}
func busyPool() *pool.Pool {
	return testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}, &auth.Auth{UID: "u2", AccessToken: "at2", ExpiresAt: 9999999999})
}
func assertBusyNoPenalty(t *testing.T, p *pool.Pool) {
	t.Helper()
	for _, a := range p.List() {
		if a.Disabled || a.Cooling || a.ErrTotal != 0 || a.BreakerFails != 0 || a.InFlight != 0 {
			t.Fatalf("busy penalized account: %+v", a)
		}
	}
}
func TestBusySameAccountRetryStreamAndAggregate(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, sse := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%v/sse=%v", stream, sse), func(t *testing.T) {
				p := busyPool()
				calls := 0
				uid := ""
				up := newFakeUpstream(t, func(a string) (int, string, bool) {
					calls++
					if uid == "" {
						uid = a
					}
					if a != uid {
						t.Error("busy rotated account")
					}
					if calls <= 3 {
						if sse {
							return 200, ": ping\r\n\r\n" + busyFrame, true
						}
						return 429, busyBody, false
					}
					return 200, sseOK, true
				})
				h := NewHandler(Config{Pool: p, Upstream: up})
				fastBusy(h, 5)
				rec := busyRequest(h, stream)
				if rec.Code != 200 || !strings.Contains(rec.Body.String(), "你好") {
					t.Fatalf("%d %s", rec.Code, rec.Body)
				}
				if calls != 4 {
					t.Fatal(calls)
				}
				assertBusyNoPenalty(t, p)
			})
		}
	}
}
func TestBusyLimitAndHints(t *testing.T) {
	for _, n := range []int{0, 1, 5} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			calls := 0
			p := busyPool()
			up := newFakeUpstream(t, func(a string) (int, string, bool) { calls++; return 429, busyBody, false })
			h := NewHandler(Config{Pool: p, Upstream: up})
			fastBusy(h, n)
			rec := busyRequest(h, false)
			if rec.Code != 429 || !strings.Contains(rec.Body.String(), `"code":"model_busy"`) {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			if calls != n+1 {
				t.Fatalf("calls=%d want %d", calls, n+1)
			}
			if rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), `"retry_after":1`) {
				t.Fatal(rec.Body)
			}
			assertBusyNoPenalty(t, p)
		})
	}
	for _, body := range []string{`{"code":6021,"msg":"queue.full.title","retry_policy":{"retry_after":120}}`, `{"code":6021,"msg":"queue.full.title","retry_policy":{"retry":false,"retry_after":13}}`} {
		calls := 0
		p := busyPool()
		h := NewHandler(Config{Pool: p, Upstream: newFakeUpstream(t, func(string) (int, string, bool) { calls++; return 429, body, false })})
		fastBusy(h, 5)
		start := time.Now()
		rec := busyRequest(h, false)
		if calls != 1 || rec.Code != 429 || time.Since(start) > time.Second {
			t.Fatalf("hint not respected: calls %d %d", calls, rec.Code)
		}
		assertBusyNoPenalty(t, p)
	}
}
func TestBusyDoesNotReplayGeneratedFrames(t *testing.T) {
	role := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n"
	tool := "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\"}}]}}]}\n\n"
	for _, prefix := range []string{role, tool} {
		for _, busyFrame := range []string{busyFrame, "data: " + busyBody + "\n\n"} {
			for _, stream := range []bool{false, true} {
				calls := 0
				p := busyPool()
				h := NewHandler(Config{Pool: p, Upstream: newFakeUpstream(t, func(string) (int, string, bool) { calls++; return 200, prefix + busyFrame, true })})
				fastBusy(h, 5)
				rec := busyRequest(h, stream)
				if !stream && (rec.Code != 429 || !strings.Contains(rec.Body.String(), "model_busy")) {
					t.Fatalf("late busy became success: %d %s", rec.Code, rec.Body)
				}
				for _, a := range p.List() {
					if a.SuccessCount != 0 {
						t.Fatal("busy recorded success")
					}
				}
				if calls != 1 {
					t.Fatal("replayed generation", calls)
				}
				assertBusyNoPenalty(t, p)
			}
		}
	}
}
func TestBusyRevalidatesAccount(t *testing.T) {
	p := busyPool()
	calls := 0
	up := newFakeUpstream(t, func(a string) (int, string, bool) {
		calls++
		for _, e := range p.List() {
			if "Bearer "+map[string]string{"u1": "at1", "u2": "at2"}[e.UID] == a {
				p.Pause(e.UID)
			}
		}
		return 429, busyBody, false
	})
	h := NewHandler(Config{Pool: p, Upstream: up})
	fastBusy(h, 5)
	rec := busyRequest(h, false)
	if calls != 1 || rec.Code != 503 {
		t.Fatalf("bypassed pause %d %d", calls, rec.Code)
	}
	assertBusyNoPenalty(t, p)
}
func TestBusyWaitReleasesLeaseAndIsCancellable(t *testing.T) {
	p := busyPool()
	p.SetMaxInFlight(1)
	seen := make(chan struct{})
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		select {
		case <-seen:
		default:
			close(seen)
		}
		return 429, busyBody, false
	})
	h := NewHandler(Config{Pool: p, Upstream: up})
	fastBusy(h, 5)
	h.busyPolicyOverride.BaseDelay = 500 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`)).WithContext(ctx)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}()
	<-seen
	deadline := time.Now().Add(time.Second)
	for {
		h.busy.mu.Lock()
		n := h.busy.waiting
		h.busy.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not waiting")
		}
		time.Sleep(time.Millisecond)
	}
	for _, e := range p.List() {
		if e.InFlight != 0 {
			t.Fatal("wait holds lease")
		}
	}
	// Another model can acquire the same account during the busy wait.
	a := p.PickExcludingForRealm(nil, "other", "")
	if a == nil || !p.AcquireForModel(a.UID, "other") {
		t.Fatal("other model blocked")
	}
	p.Release(a.UID)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel stuck")
	}
	assertBusyNoPenalty(t, p)
	h.busy.mu.Lock()
	defer h.busy.mu.Unlock()
	if h.busy.waiting != 0 {
		t.Fatal("waiter leaked")
	}
}
func TestBusyBudgetStopsAtAcceptedEvent(t *testing.T) {
	p := busyPool()
	var calls atomic.Int32
	up := &upstream.Client{ChatBaseCN: "https://fake.example", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return &http.Response{StatusCode: 429, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(busyBody))}, nil
		}
		reader, writer := io.Pipe()
		go func() {
			defer writer.Close()
			io.WriteString(writer, "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n")
			time.Sleep(80 * time.Millisecond)
			if r.Context().Err() != nil {
				t.Error("successful stream cancelled by busy timer")
			}
			io.WriteString(writer, sseOK)
		}()
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: reader}, nil
	})}}
	h := NewHandler(Config{Pool: p, Upstream: up})
	fastBusy(h, 5)
	h.busyPolicyOverride.Budget = 30 * time.Millisecond
	rec := busyRequest(h, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "你好") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
func TestBusyConfigLivePolicy(t *testing.T) {
	n := 0
	live := livecfg.New(livecfg.Snapshot{ModelBusyMaxRetries: &n})
	h := NewHandler(Config{Live: live})
	if h.busyPolicy().MaxRetries != 0 {
		t.Fatal("0 not respected")
	}
	n = 9
	live.Store(livecfg.Snapshot{ModelBusyMaxRetries: &n})
	if h.busyPolicy().MaxRetries != 9 {
		t.Fatal("hot config not applied")
	}
	if NewHandler(Config{}).busyPolicy().MaxRetries != 5 {
		t.Fatal("default not 5")
	}
}

func TestBusyBudgetSurvivesEmptyRetry(t *testing.T) {
	p := busyPool()
	var calls atomic.Int32
	up := &upstream.Client{ChatBaseCN: "https://fake.example", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return &http.Response{StatusCode: 429, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(busyBody))}, nil
		case 2:
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("data: [DONE]\n\n"))}, nil
		default:
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
	})}}
	h := NewHandler(Config{Pool: p, Upstream: up})
	fastBusy(h, 5)
	h.busyPolicyOverride.Budget = 30 * time.Millisecond
	start := time.Now()
	rec := busyRequest(h, false)
	if rec.Code != 429 || time.Since(start) > 200*time.Millisecond || calls.Load() < 2 {
		t.Fatalf("deadline lost: %d %d %s", rec.Code, calls.Load(), time.Since(start))
	}
}
