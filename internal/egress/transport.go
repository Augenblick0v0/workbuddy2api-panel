package egress

import (
	"context"

	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type proxyDialError struct{ cause error }

func (e *proxyDialError) Error() string { return "proxy dial failed" }
func (e *proxyDialError) Unwrap() error { return e.cause }
func (m *Manager) allowedIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// Metadata endpoints remain prohibited even under an explicit private CIDR.
	for _, raw := range []string{"100.100.100.200", "168.63.129.16", "fd00:ec2::254"} {
		if ip.Equal(net.ParseIP(raw)) {
			return false
		}
	}
	if !ip.IsLoopback() && !ip.IsPrivate() {
		return true
	}
	for _, cidr := range m.allowed {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
func (m *Manager) makeTransport(slot Slot) *http.Transport {
	tr := m.opts.BaseTransport.Clone()
	tr.Proxy = nil
	tr.ProxyConnectHeader = nil
	tr.GetProxyConnectHeader = nil
	tr.OnProxyConnectResponse = nil
	if slot.ID == "" {
		return tr
	}
	proxy := &url.URL{Scheme: slot.Scheme, Host: net.JoinHostPort(slot.Host, strconv.Itoa(slot.Port))}
	if slot.Username != "" || slot.Password != "" {
		proxy.User = url.UserPassword(slot.Username, slot.Password)
	}
	tr.Proxy = http.ProxyURL(proxy)
	if tr.TLSClientConfig != nil {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		tr.TLSClientConfig.InsecureSkipVerify = false
	}
	dial := tr.DialContext
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	tr.DialTLS = nil
	tr.DialTLSContext = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, &proxyDialError{e}
		}
		if host != slot.Host || port != strconv.Itoa(slot.Port) {
			return nil, &proxyDialError{errors.New("unexpected dial destination")}
		}
		var ips []net.IPAddr
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IPAddr{{IP: ip}}
		} else {
			ips, e = m.opts.Resolver.LookupIPAddr(ctx, host)
			if e != nil {
				return nil, &proxyDialError{e}
			}
		}
		if len(ips) == 0 {
			return nil, &proxyDialError{errors.New("empty DNS result")}
		}
		for _, ip := range ips {
			if !m.allowedIP(ip.IP) {
				return nil, &proxyDialError{errors.New("proxy address prohibited")}
			}
		}
		var last error
		for _, ip := range ips {
			conn, err := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, &proxyDialError{last}
	}
	tr.OnProxyConnectResponse = func(ctx context.Context, p *url.URL, req *http.Request, res *http.Response) error {
		if res.StatusCode == http.StatusProxyAuthRequired {
			return &EgressError{Code: "proxy_auth_failed", SlotID: slot.ID, Generation: slot.TransportGeneration, Stage: "connect"}
		}
		if res.StatusCode != http.StatusOK {
			return &EgressError{Code: "proxy_connect_failed", SlotID: slot.ID, Generation: slot.TransportGeneration, Stage: "connect"}
		}
		return nil
	}
	return tr
}

type ownedBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *ownedBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if e != nil {
		b.once.Do(b.release)
	}
	return n, e
}
func (b *ownedBody) Close() error { e := b.ReadCloser.Close(); b.once.Do(b.release); return e }

type probeContextKey struct{}

func (m *Manager) RoundTrip(req *http.Request) (_ *http.Response, returnedErr error) {
	defer func() {
		var ee *EgressError
		if errors.As(returnedErr, &ee) {
			// Only typed metadata, never the raw cause, proxy URL or request URL.
			// Handles reaching RoundTrip are constructed from validated slot IDs.
			log.Printf("WARN: [egress] slot=%s generation=%d stage=%s code=%s sent=%t",
				ee.SlotID, ee.Generation, ee.Stage, ee.Code, ee.Sent)
		}
	}()
	h, _ := req.Context().Value(routeContextKey{}).(*RouteHandle)
	if h == nil || h.manager != m || h.released.Load() {
		return nil, &EgressError{Code: "proxy_route_required", Stage: "context"}
	}
	probe, _ := req.Context().Value(probeContextKey{}).(bool)
	m.mu.Lock()
	c := m.snapshot.Load()
	s := m.statusLocked(c, h.SlotID)
	if h.accountUID != "" && c.PendingAccounts[h.accountUID] {
		s.State = "pending"
		m.mu.Unlock()
		return nil, routeError(s)
	}
	g := m.transports[h.transportKey]
	if h.released.Load() || g == nil || g.retired || s.Generation != h.Generation {
		m.mu.Unlock()
		return nil, &EgressError{Code: "proxy_unavailable", SlotID: h.SlotID, Generation: h.Generation, Stage: "generation"}
	}
	if !probe && s.State != "ready" && s.State != "direct" {
		m.mu.Unlock()
		return nil, routeError(s)
	}
	g.refs++
	tr := g.transport
	m.mu.Unlock()
	var sent atomic.Bool
	trace := &httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }}
	r := req.Clone(httptrace.WithClientTrace(req.Context(), trace))
	r.Header = req.Header.Clone()
	r.Header.Del("Proxy-Authorization")
	resp, err := tr.RoundTrip(r)
	if err == nil && h.SlotID != "" && resp.StatusCode == http.StatusProxyAuthRequired {
		resp.Body.Close()
		resp = nil
		err = &EgressError{Code: "proxy_auth_failed", SlotID: h.SlotID, Generation: h.Generation, Stage: "proxy_response"}
	}
	if err != nil {
		m.releaseRef(h.transportKey, false)
		var ee *EgressError
		if errors.As(err, &ee) {
			m.markUnavailable(h)
			return nil, ee
		}
		var de *proxyDialError
		if h.SlotID != "" && (errors.As(err, &de) || strings.Contains(err.Error(), "proxyconnect")) {
			code := "proxy_connect_failed"
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				code = "proxy_timeout"
			}
			m.markUnavailable(h)
			return nil, &EgressError{Code: code, SlotID: h.SlotID, Generation: h.Generation, Stage: "connect", Sent: sent.Load()}
		}
		// Ordinary upstream failures are sanitized but do not poison the proxy slot.
		code := "upstream_transport_failed"
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			code = "upstream_timeout"
		}
		return nil, &EgressError{Code: code, SlotID: h.SlotID, Generation: h.Generation, Stage: "upstream", Sent: sent.Load()}
	}
	resp.Body = &ownedBody{ReadCloser: resp.Body, release: func() { m.releaseRef(h.transportKey, false) }}
	return resp, nil
}
func (m *Manager) markUnavailable(h *RouteHandle) {
	m.mu.Lock()
	m.unavailable[h.transportKey] = true
	m.publishRuntimeLocked()
	m.mu.Unlock()
}
