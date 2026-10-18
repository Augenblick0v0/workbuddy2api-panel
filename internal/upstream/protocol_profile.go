package upstream

import "github.com/linguo2625469/workbuddy2api-panel/internal/auth"

// Existing protocol defaults are centralized here, not upgraded speculatively
// from a different client's capture. Task-specific profiles stay in their
// existing files and continue using the same fields and values.
const (
	defaultClientVersion = "5.5.4"
	defaultCliVersion    = "2.137.1"
	originRefererCN      = "https://www.codebuddy.cn"
	originRefererGlobal  = "https://www.workbuddy.ai"
)

// resolvedProtocol describes existing wire behavior by realm and purpose. It
// contains no credentials, device IDs or mutable per-request state.
type resolvedProtocol struct {
	Realm, Purpose, UserAgent, ClientVersion, CLIVersion, ClientName string
	Origin, Referer, Language, Product                               string
	MachineHeader, SessionHeader                                     bool
}

func (c *Client) protocolFor(a *auth.Auth, purpose string) resolvedProtocol {
	p := resolvedProtocol{
		Realm: "cn", Purpose: purpose, ClientVersion: c.clientVersion(),
		CLIVersion: c.cliVersion(), ClientName: c.attributionClientName(),
		Origin: originRefererCN, Language: "zh-CN",
		MachineHeader: true, SessionHeader: true,
	}
	platform := "WorkBuddy"
	if a != nil && a.IsGlobal() {
		p.Realm, p.Origin, p.Language, platform = "global", originRefererGlobal, "en-US", "WorkBuddy AI"
	}
	p.Referer = p.Origin + "/"
	p.UserAgent = "WorkBuddy/" + p.ClientVersion + " " + platform + "/" + p.ClientVersion + " CLI/" + p.CLIVersion
	if c != nil && c.UserAgent != "" {
		p.UserAgent = c.UserAgent
	}
	if purpose == "billing" || purpose == "task_billing" {
		p.MachineHeader, p.SessionHeader = false, false
		p.Origin, p.Referer = "", ""
		p.UserAgent = c.billingUA()
		if c != nil && c.UserAgent != "" {
			p.UserAgent = c.UserAgent
		}
	} else if purpose == "chat" {
		p.Product = p.ClientName
	}
	return p
}
