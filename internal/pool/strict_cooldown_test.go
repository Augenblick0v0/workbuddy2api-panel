package pool

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func TestStrictCooldownDefaultRejectsAllCooled(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "soft"})
	p.Add(&auth.Auth{UID: "breaker"})
	p.Cooldown("soft", CoolSoft, time.Hour, "synthetic rate limit")
	p.SetBreaker(1, time.Hour, time.Hour)
	p.NoteError("breaker")
	if !p.StrictCooldown() || p.Pick() != nil {
		t.Fatal("strict default must not borrow soft-cooling or broken accounts")
	}
	if p.Acquire("soft") || p.Acquire("breaker") {
		t.Fatal("lease acquisition must independently check cooling state")
	}
	p.SetStrictCooldown(false)
	if p.StrictCooldown() || p.Pick() == nil {
		t.Fatal("explicit legacy policy must still support old fallback")
	}
	p.SetStrictCooldown(true)
	if p.Pick() != nil {
		t.Fatal("hot enabling strict policy did not take effect")
	}
}

func TestStrictCooldownExpiresWithoutProbe(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u"})
	p.Cooldown("u", CoolSoft, time.Hour, "synthetic rate limit")
	if p.PickExcludingForRealm(nil, "m", "cn") != nil {
		t.Fatal("account picked before cooldown deadline")
	}
	p.mu.Lock()
	p.byUID["u"].until = time.Now().Add(-time.Second)
	p.mu.Unlock()
	a := p.PickExcludingForRealm(nil, "m", "cn")
	if a == nil || a.UID != "u" || !p.AcquireForModel("u", "m") {
		t.Fatal("normal traffic should resume after deadline without active probing")
	}
	p.Release("u")
}

func TestStrictCooldownRechecksSelectedModel(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u"})
	if p.PickExcludingForModel(nil, "m") == nil {
		t.Fatal("fixture should initially be healthy")
	}
	p.mu.Lock()
	p.byUID["u"].modelCooldowns = map[string]modelCooldown{
		"m": {Until: time.Now().Add(time.Hour)},
	}
	p.mu.Unlock()
	if p.AcquireForModel("u", "m") {
		t.Fatal("new model cooldown between Pick and Acquire must reject lease")
	}
	if p.PickExcludingForModel(nil, "m") != nil {
		t.Fatal("cooled model must not bypass strict policy")
	}
	if !p.AcquireForModel("u", "other") {
		t.Fatal("unrelated healthy model should remain usable")
	}
	p.Release("u")
}

func TestStrictCooldownPreservesSavedDeadlines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	p := New(path)
	p.Add(&auth.Auth{UID: "u"})
	p.Cooldown("u", CoolSoft, time.Hour, "synthetic rate limit")
	p.Close()
	restored := New(path)
	defer restored.Close()
	restored.Add(&auth.Auth{UID: "u"})
	if restored.Pick() != nil || restored.Acquire("u") {
		t.Fatal("restart must not bypass a persisted cooldown")
	}
}

func TestStrictCooldownConcurrentPolicyAndSelection(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u"})
	p.Cooldown("u", CoolSoft, time.Hour, "synthetic rate limit")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				p.SetStrictCooldown(true)
				if !p.StrictCooldown() || p.Pick() != nil || p.AcquireForModel("u", "m") {
					t.Error("concurrent strict policy allowed a cooled account")
					return
				}
			}
		}()
	}
	wg.Wait()
}
