package egress_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func TestProxyPendingAccountDurableHold(t *testing.T) {
	var calls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte("fixture")) }))
	defer target.Close()
	path := filepath.Join(t.TempDir(), "proxies.json")
	m, err := egress.Open(path, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.CloseIdleConnections()
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	_, err = m.Update(0, func(c *egress.Config) error {
		c.Bindings["account"] = ""
		c.PendingAccounts["account"] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertHeld := func(m *egress.Manager) {
		t.Helper()
		if m.Status("account").State != "pending" || m.Available("account") {
			t.Fatal("pending account was selectable")
		}
		_, err := m.ResolveAccount("account")
		var ee *egress.EgressError
		if !errors.As(err, &ee) || ee.Code != "proxy_account_transition" || egress.HTTPStatus(err) != 503 {
			t.Fatalf("pending resolution: %v", err)
		}
	}
	assertHeld(m)
	_, err = send(t, m, h, target.URL)
	var ee *egress.EgressError
	if !errors.As(err, &ee) || ee.Code != "proxy_account_transition" || calls.Load() != 0 {
		t.Fatalf("pre-hold account handle escaped: %v calls=%d", err, calls.Load())
	}
	snapshot := m.Snapshot()
	delete(snapshot.PendingAccounts, "account")
	assertHeld(m)
	restarted, err := egress.Open(path, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.CloseIdleConnections()
	assertHeld(restarted)
	// A manual binding edit remains held; only explicit OAuth finalization clears.
	_, err = restarted.Update(restarted.Snapshot().Revision, func(c *egress.Config) error { c.Bindings["account"] = ""; return nil })
	if err != nil {
		t.Fatal(err)
	}
	assertHeld(restarted)
	// ResolveSlot is pre-identity OAuth and intentionally independent of holds.
	oauth, err := restarted.ResolveSlot("")
	if err != nil {
		t.Fatal(err)
	}
	oauth.Release()
	_, err = restarted.Update(restarted.Snapshot().Revision, func(c *egress.Config) error { delete(c.PendingAccounts, "account"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	ready, err := restarted.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Release()
	resp, err := send(t, restarted, ready, target.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !restarted.Available("account") || calls.Load() != 1 {
		t.Fatal("explicit finalization did not unblock account")
	}
}
