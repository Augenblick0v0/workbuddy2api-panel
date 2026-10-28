package session

import (
	"testing"
	"time"
)

func TestPriorityOnlyFiltersNewAssignments(t *testing.T) {
	available := []string{"low", "high"}
	preferred := "high"
	r := New(Config{TTL: time.Hour, Available: func() []string { return available }, PreferNew: func(uids []string) []string {
		for _, uid := range uids {
			if uid == preferred {
				return []string{uid}
			}
		}
		return uids
	}})
	r.Bind("existing", "low")
	if uid, ok := r.Resolve("existing"); !ok || uid != "low" {
		t.Fatal("existing binding moved", uid)
	}
	if uid, ok := r.Resolve("new"); !ok || uid != "high" {
		t.Fatal("new ignored priority", uid)
	}
	// Preferred account already bound: priority still precedes idle lower tier.
	if uid, ok := r.Resolve("another"); !ok || uid != "high" {
		t.Fatal("idle low tier won", uid)
	}
	available = []string{"low"}
	if uid, ok := r.Resolve("new"); !ok || uid != "low" {
		t.Fatal("unavailable high tier did not fall back", uid)
	}
	available = []string{"low", "high"}
	preferred = "low"
	if uid, ok := r.Resolve("another"); !ok || uid != "high" {
		t.Fatal("changed priority moved bound session", uid)
	}
}
