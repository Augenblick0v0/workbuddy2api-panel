package main

import "testing"

func TestCompletionDefaultsAndCompatibilityOverrides(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Upstream.AccountDeviceTokenOnly || !cfg.Egress.IsolateAccountConnections || !cfg.Pool.StrictCooldown {
		t.Fatal("safety defaults not applied")
	}
	off, err := ParseConfig([]byte(`{"upstream":{"account_device_token_only":false},"egress":{"isolate_account_connections":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	if off.Upstream.AccountDeviceTokenOnly || off.Egress.IsolateAccountConnections {
		t.Fatal("explicit compatibility overrides ignored")
	}
}
