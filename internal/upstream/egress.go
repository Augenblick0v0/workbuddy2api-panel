package upstream

import (
	"context"
	"fmt"
	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
	"net/http"
)

type accountRouteKey struct{}

// InstallEgress is a startup-only operation, after transport timeout configuration.
// Naked HTTP.Do then fails locally: only sendAccount supplies the route context.
func (c *Client) InstallEgress(m *egress.Manager) {
	if m == nil {
		return
	}
	if c.PublicHTTP == nil {
		tr := newTransport()
		tr.Proxy = nil
		c.PublicHTTP = &http.Client{Timeout: c.HTTP.Timeout, Transport: tr}
	}
	c.Egress = m
	c.HTTP = &http.Client{Timeout: c.HTTP.Timeout, Transport: m, CheckRedirect: noAccountRedirect}
	timeout := c.chatHTTP().Timeout
	c.ChatHTTP = &http.Client{Timeout: timeout, Transport: m, CheckRedirect: noAccountRedirect}
}

func noAccountRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// PublicClient is isolated from account routes; preserve bare-client test injection.
func (c *Client) PublicClient() *http.Client {
	if c.PublicHTTP != nil {
		return c.PublicHTTP
	}
	return c.HTTP
}

// ForRoute pins OAuth follow-up work without copying mutexes, atomics, or caches.
// The session caller owns h; this client never releases that session reference.
func (c *Client) ForRoute(h *egress.RouteHandle) *Client {
	n := &Client{
		HTTP: c.HTTP, ChatHTTP: c.ChatHTTP, PublicHTTP: c.PublicHTTP, Egress: c.Egress, fixedRoute: h,
		HeaderTimeout: c.HeaderTimeout, IdleTimeout: c.IdleTimeout,
		UserAgent: c.UserAgent, ClientVersion: c.ClientVersion, CliVersion: c.CliVersion,
		ClientName: c.ClientName, PassthroughIP: c.PassthroughIP,
		DeviceToken: c.DeviceToken, DeviceTokenFile: c.DeviceTokenFile,
		ChatBaseCN: c.ChatBaseCN, BillingBaseCN: c.BillingBaseCN, WebBaseCN: c.WebBaseCN,
		ChatBaseGlobal: c.ChatBaseGlobal, BillingBaseGlobal: c.BillingBaseGlobal,
		GlobalEnabled: c.GlobalEnabled,
	}
	n.SanitizeFingerprints.Store(c.SanitizeFingerprints.Load())
	return n
}

func (c *Client) sendAccount(req *http.Request, a *auth.Auth, chat bool) (*http.Response, error) {
	client := c.HTTP
	if chat {
		client = c.chatHTTP()
	}
	if c.Egress == nil {
		return client.Do(req)
	}
	h := c.fixedRoute
	if h != nil {
		if err := c.Egress.CheckCurrent(h); err != nil {
			return nil, err
		}
	} else {
		if a == nil || a.UID == "" {
			return nil, &egress.EgressError{Code: "proxy_route_required", Stage: "account"}
		}
		var err error
		h, err = c.Egress.ResolveAccount(a.UID)
		if err != nil {
			return nil, err
		}
		defer h.Release()
	}
	req = req.WithContext(egress.WithRoute(req.Context(), h))
	// Keep the exact resolved key on the request/response even if bindings change.
	req = req.WithContext(context.WithValue(req.Context(), accountRouteKey{}, h.RouteKey))
	return client.Do(req)
}

func responseRouteKey(resp *http.Response) string {
	if resp == nil || resp.Request == nil {
		return ""
	}
	key, _ := resp.Request.Context().Value(accountRouteKey{}).(string)
	return key
}

func (c *Client) readFailure(err error) error {
	if c.Egress != nil {
		return &egress.EgressError{Code: "upstream_transport_failed", Stage: "body", Sent: true}
	}
	return fmt.Errorf("read body: %w", err)
}
