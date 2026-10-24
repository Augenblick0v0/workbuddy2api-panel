package egress_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func TestProxyProbeWAFIsolation(t *testing.T) {
	var probes atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("probe carried account authorization")
		}
		w.Write([]byte(`{"ip":"203.0.113.8"}`))
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.invalid/ip", ProbeMode: "legacy"})
	s := m.Snapshot()
	_, err := m.Update(s.Revision, func(c *egress.Config) error {
		s := c.Slots["slot-1"]
		s.ID = "slot-2"
		c.Slots[s.ID] = s
		c.NextSlotSeq = 3
		c.Bindings["other"] = "slot-2"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h, e := m.ResolveSlot("slot-1")
	if e != nil {
		t.Fatal(e)
	}
	m.BlockWAF(h.RouteKey, time.Now().Add(time.Minute))
	h.Release()
	if _, e = m.Probe(context.Background(), "slot-1"); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Probe(context.Background(), "slot-2"); e != nil {
		t.Fatal(e)
	}
	if m.Status("account").State != "waf_blocked" || m.Status("other").State != "waf_blocked" || m.Status("account").RouteKey != "ip:203.0.113.8" {
		t.Fatal("same known IP buckets lost WAF block")
	}
	if _, e = m.ResolveAccount("other"); e == nil {
		t.Fatal("same IP sent during WAF")
	}
	if probes.Load() != 2 {
		t.Fatal("probe request count")
	}
}

func TestProxyProbeFailureRetainsSuccessTime(t *testing.T) {
	var fail atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(500)
			return
		}
		w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.invalid/ip", ProbeMode: "legacy"})
	first, err := m.Probe(context.Background(), "slot-1")
	if err != nil || first.SuccessfulAt.IsZero() {
		t.Fatal(first, err)
	}
	fail.Store(true)
	last, err := m.Probe(context.Background(), "slot-1")
	if err == nil || last.IP != "203.0.113.9" || !last.SuccessfulAt.Equal(first.SuccessfulAt) || last.Status != "error" {
		t.Fatal("last successful evidence lost", last, err)
	}
}
func TestProxyProbeBounds(t *testing.T) {
	var redirected atomic.Int64
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer dst.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", dst.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.invalid"})
	if _, e := m.Probe(context.Background(), "slot-1"); e == nil {
		t.Fatal("redirect probe accepted")
	}
	if redirected.Load() != 0 {
		t.Fatal("probe followed redirect")
	}
	s := m.Snapshot()
	if s.ProbeResults["slot-1"].Status != "error" {
		t.Fatal("failed probe not recorded")
	}
	h, e := m.ResolveSlot("")
	if e != nil {
		t.Fatal(e)
	}
	defer h.Release()
	resp, e := send(t, m, h, dst.URL)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func TestProxyProbeResponseLimit(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat(" ", 16<<10) + "203.0.113.8"))
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.invalid"})
	result, e := m.Probe(context.Background(), "slot-1")
	if e == nil || result.Status != "error" || result.IP != "" {
		t.Fatal("oversize probe accepted")
	}
}

func TestProxyProbeWorkBuddyReachableDespiteIPFail(t *testing.T) {
	// The WorkBuddy leg answers 401 — a WAF/auth page still proves the route
	// reaches the realm's site; the ipify legs fail and stay informational.
	wb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer wb.Close()
	m := managerWithSlot(t, slotFor(t, wb.URL), egress.Options{
		AllowedCIDRs:   []string{"127.0.0.0/8"},
		WBCNTarget:     wb.URL,
		WBGlobalTarget: wb.URL,
		ProbeURL:       "http://probe.invalid/ip",
		ProbeHTTPSURL:  "http://probe.invalid/secure",
	})
	result, e := m.Probe(context.Background(), "slot-1")
	if e != nil {
		t.Fatal(e)
	}
	if result.Status != "ok" || result.SuccessfulAt.IsZero() {
		t.Fatalf("workbuddy-mode probe gated on informational IP: %+v", result)
	}
	if result.IPStatus != "error" || result.IP != "" {
		t.Fatalf("failed IP lookup should stay informational: %+v", result)
	}
	if len(result.WBTargets) != 2 {
		t.Fatalf("expected cn+global legs, got %+v", result.WBTargets)
	}
	for _, leg := range result.WBTargets {
		if leg.Status != "ok" || leg.HTTPStatus != http.StatusUnauthorized {
			t.Fatalf("401 from the realm site must count as reachable: %+v", leg)
		}
	}
}

func TestProxyProbeWorkBuddyRealmNarrowing(t *testing.T) {
	var globalProbes atomic.Int64
	wb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer wb.Close()
	global := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		globalProbes.Add(1)
		w.WriteHeader(200)
	}))
	defer global.Close()
	m := managerWithSlot(t, slotFor(t, wb.URL), egress.Options{
		AllowedCIDRs:   []string{"127.0.0.0/8"},
		WBCNTarget:     wb.URL,
		WBGlobalTarget: global.URL,
		ProbeURL:       "http://probe.invalid/ip",
	})
	result, e := m.Probe(context.Background(), "slot-1", "cn")
	if e != nil {
		t.Fatal(e)
	}
	if result.Status != "ok" || len(result.WBTargets) != 1 || result.WBTargets[0].Realm != "cn" {
		t.Fatalf("cn-only probe should walk one leg: %+v", result)
	}
	if globalProbes.Load() != 0 {
		t.Fatal("global leg probed despite cn-only realms")
	}
}

func TestProxyProbeWorkBuddyUnreachable(t *testing.T) {
	wb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	slot := slotFor(t, wb.URL)
	wb.Close() // the proxy itself is dead: every leg must fail on transport
	m := managerWithSlot(t, slot, egress.Options{
		AllowedCIDRs:   []string{"127.0.0.0/8"},
		WBCNTarget:     "http://wb.invalid/",
		WBGlobalTarget: "http://wb.invalid/",
		ProbeURL:       "http://probe.invalid/ip",
	})
	result, e := m.Probe(context.Background(), "slot-1")
	if e == nil || result.Status != "error" {
		t.Fatalf("dead proxy must fail the workbuddy gate: %+v", result)
	}
	for _, leg := range result.WBTargets {
		if leg.Status != "error" {
			t.Fatalf("dead proxy must fail every leg: %+v", leg)
		}
	}
}

func TestProxyProbeLegacyModeKeepsIPGate(t *testing.T) {
	wb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer wb.Close()
	m := managerWithSlot(t, slotFor(t, wb.URL), egress.Options{
		AllowedCIDRs:   []string{"127.0.0.0/8"},
		ProbeMode:      "legacy",
		WBCNTarget:     wb.URL,
		WBGlobalTarget: wb.URL,
		ProbeURL:       "http://probe.invalid/ip",
	})
	result, e := m.Probe(context.Background(), "slot-1")
	if e == nil || result.Status != "error" || len(result.WBTargets) != 0 {
		t.Fatalf("legacy mode must keep the IP gate and skip WB legs: %+v", result)
	}
}
