package upstream

import (
	"net/url"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

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

// ProtocolPurposeProfile is a safe view of resolved existing protocol settings.
// EndpointOrigin strips userinfo, paths, queries and fragments from overrides.
type ProtocolPurposeProfile struct {
	Realm          string `json:"realm"`
	Purpose        string `json:"purpose"`
	Identity       string `json:"identity"`
	EndpointOrigin string `json:"endpoint_origin"`
	UserAgent      string `json:"user_agent"`
	Origin         string `json:"origin"`
	Referer        string `json:"referer"`
	Language       string `json:"language"`
	Product        string `json:"product,omitempty"`
	MachineHeader  bool   `json:"machine_header"`
	SessionHeader  bool   `json:"session_header"`
}

func endpointOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (c *Client) ProtocolPurposeProfiles() []ProtocolPurposeProfile {
	if c == nil {
		return []ProtocolPurposeProfile{}
	}
	out := make([]ProtocolPurposeProfile, 0, 8)
	for _, realm := range []string{"cn", "global"} {
		a := &auth.Auth{}
		if realm == "global" {
			a.Domain = "www.workbuddy.ai"
		}
		for _, purpose := range []string{"chat", "refresh", "models", "billing"} {
			p := c.protocolFor(a, purpose)
			base := c.chatBase(a)
			if purpose == "billing" {
				base = c.billingBase(a)
			}
			out = append(out, ProtocolPurposeProfile{
				Realm: p.Realm, Purpose: purpose, Identity: "existing_workbuddy",
				EndpointOrigin: endpointOrigin(base), UserAgent: p.UserAgent,
				Origin: p.Origin, Referer: p.Referer, Language: p.Language,
				Product: p.Product, MachineHeader: p.MachineHeader, SessionHeader: p.SessionHeader,
			})
		}
	}
	return out
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
