package session

import (
	"testing"
	"time"
)

func TestProxyPeekNoReassignmentOrTTLTouch(t *testing.T) {
	r := New(Config{TTL: time.Minute, Available: func() []string { return []string{"ready"} }})
	r.Bind("fixture", "blocked")
	before := r.entries["fixture"].lastActive
	if uid, ok := r.Peek("fixture"); !ok || uid != "blocked" || r.entries["fixture"].lastActive != before {
		t.Fatal("peek mutated binding")
	}
	r.entries["fixture"] = entry{uid: "blocked", lastActive: time.Now().Add(-2 * time.Minute)}
	if _, ok := r.Peek("fixture"); ok {
		t.Fatal("peek returned expired binding")
	}
	if _, ok := r.Peek("missing"); ok {
		t.Fatal("peek assigned missing binding")
	}
	if len(r.entries) != 1 {
		t.Fatal("peek changed storage")
	}
}
