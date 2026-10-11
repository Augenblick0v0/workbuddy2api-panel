package pool

import (
	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"testing"
	"time"
)

func TestProxyPickAllPaths(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "blocked"})
	p.SetRouteAvailable(func(uid string) bool { return uid != "blocked" })
	if p.Pick() != nil || p.PickByUID("blocked") != nil || p.PickByUIDForModel("blocked", "m") != nil ||
		len(p.AvailableUIDs()) != 0 || len(p.AvailableUIDsForModel("m")) != 0 || p.ServableNow() || p.ServableForRealm("cn") {
		t.Fatal("blocked route escaped normal/sticky/available filters")
	}
	_, h, _, _, _ := p.CountsDetailed()
	if h != 0 {
		t.Fatal("route blocked counted healthy")
	}
	p.Cooldown("blocked", CoolSoft, time.Minute, "fixture")
	if p.Pick() != nil || p.PickExcludingForModel(nil, "m") != nil || p.PickExcludingForRealm(nil, "m", "cn") != nil {
		t.Fatal("blocked route escaped soft fallback")
	}
	p.Add(&auth.Auth{UID: "ready"})
	if a := p.Pick(); a == nil || a.UID != "ready" {
		t.Fatal("ready peer blocked")
	}
	p.SetRouteAvailable(nil)
	if p.PickByUID("ready") == nil {
		t.Fatal("bare pool predicate reset broken")
	}
}
