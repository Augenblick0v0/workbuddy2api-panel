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
	m := managerWithSlot(t, slotFor(t, proxy.URL), egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}, ProbeURL: "http://probe.invalid/ip"})
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
