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

func TestBusyRetryConfig(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
		bad  bool
	}{
		{`{}`, 5, false}, {`{"server":{"model_busy_max_retries":0}}`, 0, false}, {`{"server":{"model_busy_max_retries":100}}`, 100, false},
		{`{"server":{"model_busy_max_retries":-1}}`, 0, true}, {`{"server":{"model_busy_max_retries":101}}`, 0, true}, {`{"server":{"model_busy_max_retries":1.5}}`, 0, true}, {`{"server":{"model_busy_max_retries":"5"}}`, 0, true},
	} {
		c, e := ParseConfig([]byte(tc.raw))
		if tc.bad {
			if e == nil {
				t.Fatal("accepted", tc.raw)
			}
			continue
		}
		if e != nil || c.Server.ModelBusyMaxRetries != tc.want {
			t.Fatalf("%s: %+v %v", tc.raw, c.Server, e)
		}
	}
}
func TestBusyRetrySaveHotApplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"api_key":"fixture-key","custom_fixture":{"kept":true}}`), 0600)
	p := pool.New("")
	up := upstream.New()
	sch := scheduler.New(scheduler.Config{Pool: p, Upstream: up})
	live := livecfg.New(livecfg.Snapshot{})
	for _, n := range []int{0, 9, 5} {
		raw, _ := json.Marshal(map[string]any{"server": map[string]any{"model_busy_max_retries": n}})
		if _, e := saveConfig(raw, path, live, p, up, sch); e != nil {
			t.Fatal(e)
		}
		if got := live.Load().ModelBusyMaxRetries; got == nil || *got != n {
			t.Fatal("hot policy not applied", got)
		}
		data, _ := os.ReadFile(path)
		c, e := ParseConfig(data)
		if e != nil || c.Server.ModelBusyMaxRetries != n {
			t.Fatal("not persisted", e)
		}
		var doc map[string]any
		json.Unmarshal(data, &doc)
		if doc["custom_fixture"].(map[string]any)["kept"] != true {
			t.Fatal("lost unrelated config")
		}
	}
}
