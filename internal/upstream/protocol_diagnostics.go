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
// 身份字段（identity / 版本 / X-Agent-* / private_data）全部由身份矩阵解析而来，
// 仅用于面板展示，不含设备标识、凭据或每请求可变状态。
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
	ClientVersion  string `json:"client_version"`
	CLIVersion     string `json:"cli_version"`
	IdeVersion     string `json:"ide_version"`
	AgentIntent    string `json:"agent_intent,omitempty"`
	AgentType      string `json:"agent_type,omitempty"`
	AgentPurpose   string `json:"agent_purpose,omitempty"`
	PrivateData    bool   `json:"private_data"`
	MachineHeader  bool   `json:"machine_header"`
	SessionHeader  bool   `json:"session_header"`
}

// IdentityProfile 身份矩阵的一行（CN 桌面端 / global 桌面端 / CN 小程序端）。
// 字段刻意只含可公开的身份取值：不含设备标识、Token、凭据或内部地址。
type IdentityProfile struct {
	Realm         string `json:"realm"`
	Identity      string `json:"identity"`
	UserAgent     string `json:"user_agent"`
	ClientVersion string `json:"client_version"`
	CLIVersion    string `json:"cli_version"`
	IdeVersion    string `json:"ide_version"`
	Origin        string `json:"origin"`
	Language      string `json:"language"`
	Product       string `json:"product"`
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
			row := ProtocolPurposeProfile{
				Realm: p.Realm, Purpose: purpose, Identity: p.Identity,
				EndpointOrigin: endpointOrigin(base), UserAgent: p.UserAgent,
				Origin: p.Origin, Referer: p.Referer, Language: p.Language,
				Product: p.Product, ClientVersion: p.ClientVersion, CLIVersion: p.CLIVersion,
				IdeVersion:    p.ClientVersion,
				MachineHeader: p.MachineHeader, SessionHeader: p.SessionHeader,
			}
			// billing 类不注入归属头（X-Agent-* / X-Private-Data），诊断如实反映"不发送"。
			if p.MachineHeader {
				row.AgentIntent, row.AgentType, row.AgentPurpose = p.AgentIntent, p.AgentType, p.AgentPurpose
				row.PrivateData = p.PrivateData
			}
			out = append(out, row)
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
		// 版本字段取身份矩阵解析后的生效值（CN / global 版本与品牌段不同），
		// 不再是一个全局常量。
		spec := c.desktopSpecBase(a)
		profiles = append(profiles, ProtocolProfile{
			Realm: realm, UserAgent: c.userAgent(a),
			ClientVersion: spec.ClientVersion, CLIVersion: spec.CLIVersion,
			ClientName: c.attributionClientName(), UAOverride: c != nil && c.UserAgent != "",
		})
	}
	return profiles
}

// IdentityProfiles 返回身份矩阵的可展示视图（CN 桌面端 / global 桌面端 / CN 小程序端）。
// 与 accounts[] 一样是离线只读：不读凭据、不发请求、不含设备标识。
func (c *Client) IdentityProfiles() []IdentityProfile {
	desktop := func(realm string) IdentityProfile {
		a := &auth.Auth{}
		if realm == realmGlobal {
			a.Domain = "www.workbuddy.ai"
		}
		spec := c.desktopSpec(a)
		return IdentityProfile{
			Realm: spec.Realm, Identity: spec.Identity, UserAgent: spec.UserAgent,
			ClientVersion: spec.ClientVersion, CLIVersion: spec.CLIVersion,
			IdeVersion: spec.ClientVersion, Origin: spec.Origin, Language: spec.Language,
			Product: spec.Product,
		}
	}
	mp := c.mpSpec(nil)
	return []IdentityProfile{
		desktop(realmCN),
		desktop(realmGlobal),
		{
			Realm: mp.Realm, Identity: mp.Identity,
			ClientVersion: mp.ClientVersion, IdeVersion: mp.ClientVersion,
			Product: mp.Product,
		},
	}
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
