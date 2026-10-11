package egress_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func TestProxyStoreCAS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.json")
	m, err := egress.Open(path, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(0, func(c *egress.Config) error {
		c.Slots["slot-1"] = egress.Slot{ID: "slot-1", Name: "first", Enabled: true, Scheme: "http", Host: "proxy.example", Port: 8080}
		c.NextSlotSeq = 2
		c.Bindings["a"] = "slot-1"
		c.Bindings["direct"] = ""
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := m.Update(1, func(c *egress.Config) error { c.Bindings["b"] = "slot-1"; return nil })
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for e := range errs {
		if e == nil {
			successes++
		} else {
			var ee *egress.EgressError
			if errors.As(e, &ee) && ee.Code == "revision_conflict" {
				conflicts++
			} else {
				t.Fatal(e)
			}
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("CAS successes=%d conflicts=%d", successes, conflicts)
	}
	again, e := egress.Open(path, egress.Options{})
	if e != nil {
		t.Fatal(e)
	}
	s := again.Snapshot()
	if s.Revision != 2 || s.Bindings["a"] != "slot-1" || s.Slots["slot-1"].TransportGeneration != 1 {
		t.Fatalf("restart state: %+v", s)
	}
	if _, ok := s.Bindings["direct"]; !ok {
		t.Fatal("explicit direct lost")
	}
	s.Bindings["a"] = ""
	if again.Snapshot().Bindings["a"] != "slot-1" {
		t.Fatal("snapshot mutable")
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, e := egress.Open(path, egress.Options{}); e == nil {
		t.Fatal("corrupt store accepted")
	}
}

func TestProxyBindingLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.json")
	m, e := egress.Open(path, egress.Options{})
	if e != nil {
		t.Fatal(e)
	}
	var retained *egress.Config
	s, e := m.Update(0, func(c *egress.Config) error {
		retained = c
		c.NextSlotSeq = 2
		c.Slots["slot-1"] = egress.Slot{ID: "slot-1", Name: "first", Enabled: true, Scheme: "http", Host: "proxy.example", Port: 8080, TransportGeneration: 999}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	retained.Slots["slot-1"] = egress.Slot{}
	if m.Snapshot().Slots["slot-1"].Name != "first" {
		t.Fatal("callback retained mutable published map")
	}
	if s.Slots["slot-1"].TransportGeneration != 1 {
		t.Fatal("caller forged generation")
	}
	h, e := m.ResolveSlot("slot-1")
	if e != nil {
		t.Fatal(e)
	}
	if !m.InUse("slot-1") {
		t.Fatal("OAuth ref absent")
	}
	_, e = m.Update(s.Revision, func(c *egress.Config) error { delete(c.Slots, "slot-1"); return nil })
	if e == nil {
		t.Fatal("held OAuth slot deleted")
	}
	s, e = m.Update(s.Revision, func(c *egress.Config) error {
		x := c.Slots["slot-1"]
		x.Name = "renamed"
		x.TransportGeneration = 99
		c.Slots[x.ID] = x
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if s.Slots["slot-1"].TransportGeneration != 1 {
		t.Fatal("rename churned transport")
	}
	if e = m.CheckCurrent(h); e != nil {
		t.Fatal(e)
	}
	s, e = m.Update(s.Revision, func(c *egress.Config) error {
		x := c.Slots["slot-1"]
		x.Password = "new"
		c.Slots[x.ID] = x
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if s.Slots["slot-1"].TransportGeneration != 2 {
		t.Fatal("network edit missed generation")
	}
	if e = m.CheckCurrent(h); e == nil {
		t.Fatal("OAuth accepted changed generation")
	}
	h.Release()
	h.Release()
	s, e = m.Update(s.Revision, func(c *egress.Config) error { delete(c.Slots, "slot-1"); return nil })
	if e != nil {
		t.Fatal(e)
	}
	_, e = m.Update(s.Revision, func(c *egress.Config) error {
		c.Slots["slot-1"] = egress.Slot{ID: "slot-1", Enabled: true, Scheme: "http", Host: "proxy.example", Port: 8080}
		return nil
	})
	if e == nil {
		t.Fatal("deleted ID reused")
	}
}
func TestProxyStoreRequiredSchema(t *testing.T) {
	p := filepath.Join(t.TempDir(), "proxies.json")
	if e := os.WriteFile(p, []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := egress.Open(p, egress.Options{}); e == nil {
		t.Fatal("missing schema accepted")
	}
}

func TestProxyStoreFailureKeepsSnapshot(t *testing.T) {
	for _, stage := range []string{"sync", "rename"} {
		t.Run(stage, func(t *testing.T) {
			var fail atomic.Bool
			hooks := &egress.StoreHooks{Sync: func(f *os.File) error {
				if fail.Load() && stage == "sync" {
					return os.ErrPermission
				}
				return f.Sync()
			}, Rename: func(old, new string) error {
				if fail.Load() && stage == "rename" {
					return os.ErrPermission
				}
				return os.Rename(old, new)
			}}
			path := filepath.Join(t.TempDir(), "proxies.json")
			m, e := egress.Open(path, egress.Options{StoreHooks: hooks})
			if e != nil {
				t.Fatal(e)
			}
			_, e = m.Update(0, func(c *egress.Config) error { c.Bindings["kept"] = ""; return nil })
			if e != nil {
				t.Fatal(e)
			}
			fail.Store(true)
			_, e = m.Update(1, func(c *egress.Config) error { c.Bindings["must-not-publish"] = ""; return nil })
			if e == nil {
				t.Fatal("write failure ignored")
			}
			if m.Snapshot().Revision != 1 {
				t.Fatal("failed snapshot published")
			}
			again, e := egress.Open(path, egress.Options{})
			if e != nil {
				t.Fatal(e)
			}
			if again.Snapshot().Revision != 1 {
				t.Fatal("failed transaction changed disk")
			}
			if _, ok := again.Snapshot().Bindings["must-not-publish"]; ok {
				t.Fatal("failed binding persisted")
			}
		})
	}
}
func TestProxyAvailabilityDuringBlockedWrite(t *testing.T) {
	var armed atomic.Bool
	entered := make(chan struct{})
	release := make(chan struct{})
	hooks := &egress.StoreHooks{Sync: func(f *os.File) error {
		if armed.Load() {
			armed.Store(false)
			close(entered)
			<-release
		}
		return f.Sync()
	}}
	m, e := egress.Open(filepath.Join(t.TempDir(), "proxies.json"), egress.Options{StoreHooks: hooks})
	if e != nil {
		t.Fatal(e)
	}
	armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, e := m.Update(0, func(c *egress.Config) error { c.Bindings["account"] = ""; return nil })
		done <- e
	}()
	<-entered
	available := make(chan bool, 1)
	go func() { available <- m.Available("account") }()
	select {
	case ok := <-available:
		if !ok {
			t.Error("old direct snapshot unavailable")
		}
	case <-time.After(time.Second):
		t.Error("availability blocked behind store I/O")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestProxyStorePOSIXPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode assertion runs on Linux")
	}
	p := filepath.Join(t.TempDir(), "proxies.json")
	m, e := egress.Open(p, egress.Options{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Update(0, func(c *egress.Config) error { return nil }); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(p)
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if e = os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = egress.Open(p, egress.Options{}); e == nil {
		t.Fatal("insecure secret store accepted")
	}
}
func TestProxyStorePostCommitSync(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory sync Linux only")
	}
	var calls atomic.Int64
	hooks := &egress.StoreHooks{Sync: func(f *os.File) error {
		if calls.Add(1) == 3 {
			return os.ErrPermission
		}
		return f.Sync()
	}}
	p := filepath.Join(t.TempDir(), "proxies.json")
	m, e := egress.Open(p, egress.Options{StoreHooks: hooks})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Update(0, func(c *egress.Config) error { c.Bindings["committed"] = ""; return nil }); e != nil {
		t.Fatal("rename commit misreported failure", e)
	}
	again, e := egress.Open(p, egress.Options{})
	if e != nil {
		t.Fatal(e)
	}
	if again.Snapshot().Revision != 1 || m.Snapshot().Revision != 1 {
		t.Fatal("post-rename fsync failure split revisions")
	}
}
