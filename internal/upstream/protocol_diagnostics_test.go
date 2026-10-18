package upstream

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func TestProtocolDiagnosticsProfilesUseExistingEffectiveSettings(t *testing.T) {
	c := &Client{ClientVersion: "fixture-client", CliVersion: "fixture-cli", ClientName: "fixture-name"}
	for _, p := range c.ProtocolProfiles() {
		a := &auth.Auth{}
		if p.Realm == "global" {
			a.Domain = "www.workbuddy.ai"
		}
		if p.UserAgent != c.userAgent(a) || p.ClientVersion != c.clientVersion() ||
			p.CLIVersion != c.cliVersion() || p.ClientName != c.attributionClientName() || p.UAOverride {
			t.Fatalf("not effective configuration: %+v", p)
		}
	}
	c.UserAgent = "synthetic-custom-UA"
	for _, p := range c.ProtocolProfiles() {
		if p.UserAgent != c.UserAgent || !p.UAOverride {
			t.Fatal("override not represented", p)
		}
	}
	var nilClient *Client
	if len(nilClient.ProtocolProfiles()) != 2 {
		t.Fatal("nil-safe default profiles lost")
	}
}

func TestProtocolDiagnosticsTokenSourcesNoSecretsOrFileRead(t *testing.T) {
	file := filepath.Join(t.TempDir(), "synthetic-token")
	if err := os.WriteFile(file, []byte("synthetic-file-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Client{DeviceToken: "synthetic-global-secret", DeviceTokenFile: file}
	a := &auth.Auth{DeviceToken: "synthetic-account-secret"}
	assertSource := func(source string, present *bool) {
		t.Helper()
		d := c.DeviceTokenDiagnostic(a)
		if d.Source != source || (d.Present == nil) != (present == nil) ||
			(present != nil && *d.Present != *present) {
			t.Fatalf("source/presence: %+v", d)
		}
		raw, _ := json.Marshal(d)
		for _, secret := range []string{"synthetic-", file, "secret"} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("secret or path disclosure", string(raw))
			}
		}
	}
	yes, no := true, false
	assertSource("account", &yes)
	a.DeviceToken = ""
	assertSource("global", &yes)
	c.DeviceToken = ""
	assertSource("file", nil)
	// Missing/unreadable paths yield the same DTO: diagnostics cannot assert the
	// file content is present and never calls the existing file resolver/cache.
	c.DeviceTokenFile = filepath.Join(t.TempDir(), "does-not-exist")
	assertSource("file", nil)
	if !c.SharedDeviceTokenFallbackConfigured() {
		t.Fatal("file configuration risk not reported")
	}
	c.DeviceTokenFile = ""
	assertSource("none", &no)
	if c.SharedDeviceTokenFallbackConfigured() {
		t.Fatal("false positive fallback")
	}
}
