package server

import (
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

func TestStrictCooldownStopsBeforeAnyUpstreamRequest(t *testing.T) {
	p := testPoolWith(&auth.Auth{UID: "u", AccessToken: "synthetic-access", ExpiresAt: 9999999999})
	p.Cooldown("u", pool.CoolSoft, time.Hour, "synthetic rate limit")
	var requests atomic.Int64
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		requests.Add(1)
		return 200, sseOK, true
	})
	h := NewHandler(Config{Pool: p, Upstream: up})
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions",
			strings.NewReader(`{"model":"glm-5.2","messages":[{"role":"user","content":"fixture"}],"stream":false}`)))
		return w
	}
	if w := request(); w.Code != 503 || requests.Load() != 0 {
		t.Fatalf("strict mode must stop locally: status=%d requests=%d", w.Code, requests.Load())
	}
	p.SetStrictCooldown(false)
	if w := request(); w.Code != 200 || requests.Load() != 1 {
		t.Fatalf("control must actually reach fake upstream: status=%d requests=%d body=%s",
			w.Code, requests.Load(), w.Body)
	}
	if st, ok := p.Status("u"); !ok || st.InFlight != 0 {
		t.Fatalf("lease not released: %+v", st)
	}
}
