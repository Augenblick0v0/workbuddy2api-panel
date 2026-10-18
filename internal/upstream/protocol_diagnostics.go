package upstream

import "github.com/linguo2625469/workbuddy2api-panel/internal/auth"

// ProtocolProfile is an explicit allowlist, not a serialization of request headers
// or Client. These are the existing effective values; diagnostics never mutate them.
type ProtocolProfile struct {
	Realm         string `json:"realm"`
	UserAgent     string `json:"user_agent"`
	ClientVersion string `json:"client_version"`
	CLIVersion    string `json:"cli_version"`
	ClientName    string `json:"client_name"`
	UAOverride    bool   `json:"ua_override"`
}

func (c *Client) ProtocolProfiles() []ProtocolProfile {
	profiles := make([]ProtocolProfile, 0, 2)
	for _, realm := range []string{"cn", "global"} {
		// Only a synthetic non-secret account is needed to resolve realm-specific
		// defaults. No real credentials, headers, requests, or token files are read.
		a := &auth.Auth{}
		if realm == "global" {
			a.Domain = "www.workbuddy.ai"
		}
		profiles = append(profiles, ProtocolProfile{
			Realm: realm, UserAgent: c.userAgent(a),
			ClientVersion: c.clientVersion(), CLIVersion: c.cliVersion(),
			ClientName: c.attributionClientName(), UAOverride: c != nil && c.UserAgent != "",
		})
	}
	return profiles
}

// DeviceTokenDiagnostic reveals only source and presence, never token bytes or
// hashes. A configured file is deliberately not opened: its presence is unknown.
type DeviceTokenDiagnostic struct {
	Source     string `json:"source"`
	Configured bool   `json:"configured"`
	Present    *bool  `json:"present,omitempty"`
}

func (c *Client) DeviceTokenDiagnostic(a *auth.Auth) DeviceTokenDiagnostic {
	hasAccountToken := false
	if a != nil {
		a.Lock()
		hasAccountToken = a.DeviceToken != ""
		a.Unlock()
	}
	present := true
	if hasAccountToken {
		return DeviceTokenDiagnostic{Source: "account", Configured: true, Present: &present}
	}
	if c != nil && c.DeviceToken != "" {
		return DeviceTokenDiagnostic{Source: "global", Configured: true, Present: &present}
	}
	if c != nil && c.DeviceTokenFile != "" {
		return DeviceTokenDiagnostic{Source: "file", Configured: true}
	}
	present = false
	return DeviceTokenDiagnostic{Source: "none", Present: &present}
}

// SharedDeviceTokenFallbackConfigured reports a configuration risk, not proof
// that a token is actually shared. Account-specific tokens retain precedence.
func (c *Client) SharedDeviceTokenFallbackConfigured() bool {
	return c != nil && (c.DeviceToken != "" || c.DeviceTokenFile != "")
}
