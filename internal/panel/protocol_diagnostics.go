package panel

import (
	"net/http"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

type protocolRouteDiagnostic struct {
	State      string `json:"state"`
	SlotID     string `json:"slot_id"`
	Generation uint64 `json:"generation"`
}

type protocolAccountDiagnostic struct {
	UID         string                         `json:"uid"`
	Realm       string                         `json:"realm"`
	DeviceToken upstream.DeviceTokenDiagnostic `json:"device_token"`
	Route       protocolRouteDiagnostic        `json:"route"`
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
		accounts = append(accounts, protocolAccountDiagnostic{
			UID: status.UID, Realm: realm,
			DeviceToken: p.cfg.Upstream.DeviceTokenDiagnostic(a),
			Route:       route,
		})
	}
	if len(accounts) > 1 && p.cfg.Upstream.SharedDeviceTokenFallbackConfigured() {
		warnings = append(warnings, "shared_device_token_fallback_configured")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version":  1,
		"task_reporting":  "unchanged",
		"strict_cooldown": p.cfg.Pool.StrictCooldown(),
		"accounts":        accounts,
		"profiles":        p.cfg.Upstream.ProtocolProfiles(),
		"warnings":        warnings,
	})
}
