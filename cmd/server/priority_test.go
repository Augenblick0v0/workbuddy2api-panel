package main

import (
	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/session"
	"testing"
	"time"
)

func TestPrioritySessionWiring(t *testing.T) {
	p := pool.New("")
	p.Add(&auth.Auth{UID: "low"})
	p.Add(&auth.Auth{UID: "high"})
	p.Add(&auth.Auth{UID: "global", Domain: "workbuddy.ai"})
	p.SetPriority("high", 10)
	p.SetPriority("global", 100)
	r := session.New(session.Config{TTL: time.Hour, AvailableForModel: realmAwareAvailableForModel(p), PreferNew: p.PreferNew})
	r.Bind("existing", "low")
	if uid, ok := r.ResolveForModel("existing", "cn:m"); !ok || uid != "low" {
		t.Fatal(uid)
	}
	if uid, ok := r.ResolveForModel("new", "cn:m"); !ok || uid != "high" {
		t.Fatal(uid)
	}
	p.Pause("high")
	if uid, ok := r.ResolveForModel("new", "cn:m"); !ok || uid != "low" {
		t.Fatal(uid)
	}
	if uid, ok := r.ResolveForModel("world", "global:m"); !ok || uid != "global" {
		t.Fatal(uid)
	}
}
