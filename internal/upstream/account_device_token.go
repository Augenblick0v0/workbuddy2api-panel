package upstream

import "github.com/linguo2625469/workbuddy2api-panel/internal/auth"

func accountDeviceToken(a *auth.Auth) string {
	if a == nil {
		return ""
	}
	a.Lock()
	defer a.Unlock()
	return a.DeviceToken
}

// APIDeviceTokenDiagnostic describes the actual chat-API policy independently
// of task/billing token fallback. No token files are accessed.
func (c *Client) APIDeviceTokenDiagnostic(a *auth.Auth) DeviceTokenDiagnostic {
	if c == nil || !c.AccountDeviceTokenOnly.Load() || accountDeviceToken(a) != "" {
		return c.DeviceTokenDiagnostic(a)
	}
	no := false
	return DeviceTokenDiagnostic{Source: "none", Present: &no}
}
