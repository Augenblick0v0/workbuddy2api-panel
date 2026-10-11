package egress_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func TestProxyWAFLateResponseCanonicalRoute(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.8"}`))
	}))
	defer proxy.Close()
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{
		AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.invalid/ip",
	})
	_, err := m.Update(m.Snapshot().Revision, func(c *egress.Config) error {
		s := c.Slots["slot-1"]
		s.ID = "slot-2"
		c.Slots[s.ID] = s
		c.NextSlotSeq = 3
		c.Bindings["other"] = s.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// An in-flight response still carries this pre-probe unresolved key.
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	if h.RouteKey != "slot-1:1" {
		t.Fatalf("unexpected initial key %q", h.RouteKey)
	}
	for _, id := range []string{"slot-1", "slot-2"} {
		if _, err := m.Probe(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if key := m.CanonicalRouteKey(h.RouteKey); key != "ip:203.0.113.8" {
		t.Fatal("unresolved handle not canonicalized", key)
	}
	m.BlockWAF(h.RouteKey, time.Now().Add(time.Minute))
	if m.Available("account") || m.Available("other") {
		t.Fatal("late WAF response failed to block equal current IPs")
	}
}

func TestProxyWAFCanonicalPreservesHistoricalIPAndGeneration(t *testing.T) {
	m := managerWithSlot(t, egress.Slot{ID: "slot-1", Name: "fixture", Enabled: true, Scheme: "http", Host: "proxy.invalid", Port: 8080}, egress.Options{})
	_, err := m.Update(m.Snapshot().Revision, func(c *egress.Config) error {
		c.ProbeResults["slot-1"] = egress.ProbeResult{SlotID: "slot-1", Generation: 1, IP: "203.0.113.8", Status: "ok"}
		s := c.Slots["slot-1"]
		s.ID = "slot-2"
		c.Slots[s.ID] = s
		c.NextSlotSeq = 3
		c.Bindings["other"] = s.ID
		c.ProbeResults[s.ID] = egress.ProbeResult{SlotID: s.ID, Generation: 1, IP: "203.0.113.8", Status: "ok"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	_, err = m.Update(m.Snapshot().Revision, func(c *egress.Config) error {
		p := c.ProbeResults["slot-1"]
		p.IP = "203.0.113.9"
		c.ProbeResults[p.SlotID] = p
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.CanonicalRouteKey(h.RouteKey) != h.RouteKey {
		t.Fatal("historical known IP remapped")
	}
	m.BlockWAF(h.RouteKey, time.Now().Add(time.Minute))
	if !m.Available("account") || m.Available("other") {
		t.Fatal("old known IP incorrectly blocked a new unrelated IP")
	}
	_, err = m.Update(m.Snapshot().Revision, func(c *egress.Config) error {
		s := c.Slots["slot-1"]
		s.Port++
		c.Slots[s.ID] = s
		p := c.ProbeResults["slot-1"]
		p.Generation = 2
		p.IP = "203.0.113.10"
		c.ProbeResults[p.SlotID] = p
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.CanonicalRouteKey("slot-1:1") != "slot-1:1" || m.CanonicalRouteKey("slot-1:2") != "ip:203.0.113.10" {
		t.Fatal("generation boundary aliased")
	}
}
