package egress_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func TestProxyFaultRecoversWithoutManualProbe(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var proxied, direct atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
		io.WriteString(w, "unexpected-direct")
	}))
	defer target.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		io.WriteString(w, "recovered-through-original-proxy")
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{
		AllowedCIDRs: []string{"127.0.0.0/8"}, FailureCooldown: 200 * time.Millisecond,
	})
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	_, err = send(t, m, h, target.URL)
	var ee *egress.EgressError
	if !errors.As(err, &ee) || ee.Code != "proxy_auth_failed" {
		t.Fatalf("real proxy failure not returned: %v", err)
	}
	status := m.Status("account")
	if status.State != "unavailable" || status.RetryAfter < 1 {
		t.Fatalf("failure has no bounded recovery deadline: %+v", status)
	}
	if _, err := m.ResolveAccount("account"); err == nil {
		t.Fatal("new request bypassed active fault cooldown")
	}
	if proxied.Load() != 1 || direct.Load() != 0 {
		t.Fatal("failed request replayed or fell through")
	}
	fail.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for !m.Available("account") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !m.Available("account") {
		t.Fatalf("recovered proxy still requires a manual exit probe: %+v", m.Status("account"))
	}
	next, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Release()
	if next.SlotID != h.SlotID || next.Generation != h.Generation {
		t.Fatal("automatic recovery changed the fixed proxy route")
	}
	response, err := send(t, m, next, target.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "recovered-through-original-proxy" || proxied.Load() != 2 || direct.Load() != 0 {
		t.Fatalf("wrong recovery route/body: %q proxy=%d direct=%d", body, proxied.Load(), direct.Load())
	}
	fail.Store(true)
	_, err = send(t, m, next, target.URL)
	if !errors.As(err, &ee) || ee.Code != "proxy_auth_failed" || m.Available("account") || proxied.Load() != 3 {
		t.Fatal("continued outage did not start another bounded cooldown", err)
	}
	// A timer must never clear the independent WAF or disabled protections.
	m.BlockWAF(next.RouteKey, time.Now().Add(time.Minute))
	time.Sleep(210 * time.Millisecond)
	if m.Available("account") || m.Status("account").State != "waf_blocked" {
		t.Fatal("fault expiry bypassed WAF")
	}
	_, err = m.Update(m.Snapshot().Revision, func(c *egress.Config) error {
		slot := c.Slots["slot-1"]
		slot.Enabled = false
		c.Slots[slot.ID] = slot
		return nil
	})
	if err != nil || m.Available("account") || m.Status("account").State != "disabled" {
		t.Fatal("fault expiry bypassed disabled slot", err)
	}
}

func TestDefaultProxyFaultPauseHasFifteenSecondLimit(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	if _, err := send(t, m, h, "http://target.invalid/"); err == nil {
		t.Fatal("expected proxy fault")
	}
	status := m.Status("account")
	if status.State != "unavailable" || status.RetryAfter < 1 || status.RetryAfter > 15 {
		t.Fatalf("default fault pause is not bounded by 15 seconds: %+v", status)
	}
}
