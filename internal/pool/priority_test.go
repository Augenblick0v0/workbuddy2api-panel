package pool

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func priorityPool(t *testing.T) *Pool {
	t.Helper()
	p := New("")
	for _, uid := range []string{"high", "low"} {
		p.Add(&auth.Auth{UID: uid})
		p.SetCredits(uid, 1000, 0)
	}
	if !p.SetPriority("high", 10) {
		t.Fatal("set priority")
	}
	return p
}

func TestPriorityBeforeCostAndSameTierRotation(t *testing.T) {
	p := priorityPool(t)
	p.NoteModelCost("low", "m", 0, 1000)
	for i := 0; i < 20; i++ {
		if a := p.PickExcludingForModel(nil, "m"); a == nil || a.UID != "high" {
			t.Fatalf("got %v", a)
		}
	}
	p.SetPriority("low", 10)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		seen[p.Pick().UID] = true
	}
	if len(seen) != 2 {
		t.Fatalf("equal priority rotation: %v", seen)
	}
	if a := p.PickByUIDForModel("low", "m"); a == nil {
		t.Fatal("explicit/sticky lower priority rejected")
	}
}

func TestPriorityUnavailableFallsBack(t *testing.T) {
	cases := map[string]func(*Pool){
		"paused":   func(p *Pool) { p.Pause("high") },
		"disabled": func(p *Pool) { p.Disable("high", "test") },
		"cooling":  func(p *Pool) { p.Cooldown("high", CoolSoft, time.Hour, "test") },
		"model":    func(p *Pool) { p.CooldownSoftForModel("high", time.Hour, time.Now().Add(time.Hour), "m", "test") },
		"breaker":  func(p *Pool) { p.byUID["high"].breakerUntil = time.Now().Add(time.Hour) },
		"full": func(p *Pool) {
			p.SetMaxInFlight(1)
			if !p.Acquire("high") {
				t.Fatal("acquire")
			}
		},
		"tried": func(p *Pool) {},
		"proxy": func(p *Pool) { p.SetRouteAvailable(func(uid string) bool { return uid != "high" }) },
		"floor": func(p *Pool) {
			p.SetCreditFloor(100)
			p.SetCredits("high", 1, 0)
			p.NoteModelCost("high", "m", 1, 1000)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := priorityPool(t)
			change(p)
			tried := map[string]bool{}
			if name == "tried" {
				tried["high"] = true
			}
			if a := p.PickExcludingForRealm(tried, "m", "cn"); a == nil || a.UID != "low" {
				t.Fatalf("got %v", a)
			}
			if name != "tried" {
				got := p.PreferNew(p.WeightedAvailableUIDsForModelRealm("m", "cn"))
				if !reflect.DeepEqual(got, []string{"low"}) {
					t.Fatalf("session candidates %v", got)
				}
			}
		})
	}
}

func TestPriorityPersistenceAndLegacy(t *testing.T) {
	fp := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(fp, []byte(`{"accounts":{"low":{"credits":1000}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := New(fp)
	defer p.Close()
	if s, _ := p.Status("low"); s.Priority != 0 {
		t.Fatal(s)
	}
	p.Add(&auth.Auth{UID: "high"})
	p.SetPriority("high", 100)
	p.Pause("high")
	p.Flush()
	q := New(fp)
	defer q.Close()
	if s, _ := q.Status("high"); s.Priority != 100 || !s.Paused {
		t.Fatal(s)
	}
	r := New("")
	r.adoptSnapshot(snapshot{stateFile: p.stateOverviewLocked()})
	if s, _ := r.Status("high"); s.Priority != 100 {
		t.Fatal(s)
	}
	if p.SetPriority("missing", 1) || p.SetPriority("high", -1) || p.SetPriority("high", 101) {
		t.Fatal("accepted invalid priority")
	}
	p.Add(&auth.Auth{UID: "high"})
	p.Revive("high")
	if s, _ := p.Status("high"); s.Priority != 100 {
		t.Fatal("upsert/revive reset priority")
	}
	p.SetPriority("high", 0)
	p.Flush()
	q2 := New(fp)
	defer q2.Close()
	if s, _ := q2.Status("high"); s.Priority != 0 {
		t.Fatal("reset not persisted")
	}
}

func TestPriorityRealmAndWeightedCandidates(t *testing.T) {
	p := priorityPool(t)
	p.Add(&auth.Auth{UID: "global", Domain: "workbuddy.ai"})
	p.SetPriority("global", 100)
	if a := p.PickExcludingForRealm(nil, "m", "cn"); a == nil || a.UID != "high" {
		t.Fatal(a)
	}
	if got := p.PreferNew([]string{"low", "high", "high", "high"}); !reflect.DeepEqual(got, []string{"high", "high", "high"}) {
		t.Fatal(got)
	}
	if got := p.PreferNew([]string{"missing"}); len(got) != 0 {
		t.Fatal(got)
	}
}
