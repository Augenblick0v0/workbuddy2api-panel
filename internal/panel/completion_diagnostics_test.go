package panel

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func TestCompletionDiagnosticsReportsRestrictionAndAPITokenPolicy(t *testing.T) {
	pl := pool.New("")
	pl.Add(&auth.Auth{UID: "fixture", AccessToken: "synthetic-secret"})
	pl.Disable("fixture", "account banned by upstream (11140 request illegal), re-login required")
	c := upstream.New()
	c.DeviceToken = "synthetic-shared-secret"
	c.AccountDeviceTokenOnly.Store(true)
	pn := New(Config{Pool: pl, Upstream: c, APIKey: "fixture-key"})
	w := diagnosticsCall(pn, "fixture-key")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var result struct {
		Accounts []protocolAccountDiagnostic       `json:"accounts"`
		Alerts   int                               `json:"disabled_account_alerts"`
		OnlyOwn  bool                              `json:"api_account_device_token_only"`
		Purposes []upstream.ProtocolPurposeProfile `json:"purpose_profiles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Alerts != 1 || !result.OnlyOwn || len(result.Purposes) != 8 ||
		result.Accounts[0].Alert != "upstream_account_restricted" ||
		result.Accounts[0].APIDeviceToken.Source != "none" {
		t.Fatalf("wrong restriction/token policy diagnostic: %+v", result)
	}
	for _, secret := range []string{"synthetic-secret", "synthetic-shared-secret", "re-login required"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("diagnostic exposed a credential or raw reason", secret)
		}
	}
	if pl.Pick() != nil {
		t.Fatal("diagnostic changed restricted account state")
	}
}
