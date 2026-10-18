package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/scheduler"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func TestStrictCooldownConfigDefaultsAndExplicitLegacy(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{`{}`, true},
		{`{"pool":{"strict_cooldown":true}}`, true},
		{`{"pool":{"strict_cooldown":false}}`, false},
	} {
		cfg, err := ParseConfig([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Pool.StrictCooldown != tc.want {
			t.Fatalf("raw=%s strict=%v want=%v", tc.raw, cfg.Pool.StrictCooldown, tc.want)
		}
	}
}

func TestStrictCooldownSaveHotAppliesWithoutChangingTaskConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	const original = `{"api_key":"fixture-key","schedule":{"activity_enabled":false,"growth_enabled":false},"custom_fixture":{"kept":true}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	p := pool.New("")
	up := upstream.New()
	sch := scheduler.New(scheduler.Config{Pool: p, Upstream: up})
	live := livecfg.New(livecfg.Snapshot{APIKey: "fixture-key"})
	for _, enabled := range []bool{false, true} {
		raw, _ := json.Marshal(map[string]any{"pool": map[string]any{"strict_cooldown": enabled}})
		if _, err := saveConfig(raw, path, live, p, up, sch); err != nil {
			t.Fatal(err)
		}
		if p.StrictCooldown() != enabled {
			t.Fatalf("saved=%v runtime=%v", enabled, p.StrictCooldown())
		}
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(saved, &doc); err != nil {
			t.Fatal(err)
		}
		schedule := doc["schedule"].(map[string]any)
		if schedule["activity_enabled"] != false || schedule["growth_enabled"] != false ||
			doc["custom_fixture"].(map[string]any)["kept"] != true {
			t.Fatal("hot policy update changed task settings or discarded unknown configuration")
		}
	}
}
