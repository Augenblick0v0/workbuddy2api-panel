package panel

import (
	"net/http"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

type protocolRouteDiagnostic struct {
	State      string `json:"state"`
	SlotID     string `json:"slot_id"`
	Generation uint64 `json:"generation"`
}

type protocolAccountDiagnostic struct {
	UID            string                         `json:"uid"`
	Realm          string                         `json:"realm"`
	DeviceToken    upstream.DeviceTokenDiagnostic `json:"device_token"`
	APIDeviceToken upstream.DeviceTokenDiagnostic `json:"api_device_token"`
	Route          protocolRouteDiagnostic        `json:"route"`
	Alert          string                         `json:"alert,omitempty"`
}

// protocolDiagnostics is offline and read-only: no upper-layer HTTP methods or
// token resolvers are called, and proxy addresses/credentials never enter its DTO.
func (p *Panel) protocolDiagnostics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if p.apiKey() == "" {
		writeErr(w, http.StatusServiceUnavailable, "protocol_diagnostics_auth_required")
		return
	}
	if p.cfg.Pool == nil || p.cfg.Upstream == nil {
		writeErr(w, http.StatusNotImplemented, "protocol_diagnostics_not_available")
		return
	}
	accounts := make([]protocolAccountDiagnostic, 0)
	warnings := make([]string, 0)
	alerts := 0
	for _, status := range p.cfg.Pool.List() {
		a := p.cfg.Pool.AuthByUID(status.UID)
		if a == nil {
			continue
		}
		// Realm() locks Auth itself, so call it outside the token snapshot lock.
		realm := a.Realm()
		route := protocolRouteDiagnostic{State: "not_configured"}
		if p.cfg.Egress != nil {
			current := p.cfg.Egress.Status(status.UID)
			route = protocolRouteDiagnostic{
				State: current.State, SlotID: current.SlotID, Generation: current.Generation,
			}
		}
		alert := ""
		if status.Disabled {
			alert = "account_disabled_requires_review"
			if strings.Contains(strings.ToLower(status.DisabledReason), "request illegal") ||
				strings.Contains(strings.ToLower(status.DisabledReason), "banned") {
				alert = "upstream_account_restricted"
			}
			alerts++
		} else if status.BreakerUntil.After(time.Now()) {
			alert = "account_circuit_open"
		}
		accounts = append(accounts, protocolAccountDiagnostic{
			UID: status.UID, Realm: realm,
			DeviceToken:    p.cfg.Upstream.DeviceTokenDiagnostic(a),
			APIDeviceToken: p.cfg.Upstream.APIDeviceTokenDiagnostic(a),
			Route:          route,
			Alert:          alert,
		})
	}
	if len(accounts) > 1 && p.cfg.Upstream.SharedDeviceTokenFallbackConfigured() {
		warnings = append(warnings, "shared_device_token_fallback_configured")
	}
	if alerts > 0 {
		warnings = append(warnings, "disabled_accounts_require_review")
	}
	isolation := false
	if p.cfg.Egress != nil {
		isolation = p.cfg.Egress.IsolatesAccountConnections()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version":                 1,
		"task_reporting":                 "unchanged",
		"strict_cooldown":                p.cfg.Pool.StrictCooldown(),
		"accounts":                       accounts,
		"profiles":                       p.cfg.Upstream.ProtocolProfiles(),
		"purpose_profiles":               p.cfg.Upstream.ProtocolPurposeProfiles(),
		"api_account_device_token_only":  p.cfg.Upstream.AccountDeviceTokenOnly.Load(),
		"account_connection_isolation":   isolation,
		"disabled_account_alerts":        alerts,
		"device_id_policy":               "per_account_stable_desktop_unified_mp_unique",
		"international_identity_upgrade": "applied_global_desktop_5_8_4",
		"identities":                     p.cfg.Upstream.IdentityProfiles(),
		"warnings":                       warnings,
	})
}
