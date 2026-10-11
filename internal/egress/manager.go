package egress

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (m *Manager) releaseRef(key string, caller bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g := m.transports[key]; g != nil {
		g.refs--
		if caller {
			g.callers.Add(-1)
		}
		if g.refs == 0 && g.retired {
			g.transport.CloseIdleConnections()
			delete(m.transports, key)
		}
	}
}
func (m *Manager) routeKeyLocked(c *Config, id string, g uint64) string {
	if p, ok := c.ProbeResults[id]; ok && p.Generation == g {
		if ip := routeIP(p); ip != "" {
			return "ip:" + ip
		}
	}
	return transportKey(id, g)
}

// Plaintext HTTP observations are display-only. Only successful HTTPS evidence
// (or a pre-upgrade successful probe) may identify a shared WAF exit bucket.
func routeIP(p ProbeResult) string {
	if p.VerifiedIP != "" {
		return p.VerifiedIP
	}
	if p.HTTPSStatus == "" && (p.Status == "ok" || !p.SuccessfulAt.IsZero()) {
		return p.IP
	}
	return ""
}

// CanonicalRouteKey promotes an unresolved route to its subsequently learned
// IP only while that exact slot generation remains current. An already known IP
// is historical request evidence, not an alias to a slot's newer observed IP.
// This is an atomic-snapshot read and performs no network, disk, or lock I/O.
func (m *Manager) CanonicalRouteKey(key string) string {
	return m.canonicalRouteKey(m.snapshot.Load(), key)
}

func (m *Manager) canonicalRouteKey(c *Config, key string) string {
	if key == "direct" {
		return m.routeKeyLocked(c, "", 0)
	}
	if !strings.HasPrefix(key, "slot-") {
		return key
	}
	sep := strings.LastIndexByte(key, ':')
	if sep < 0 {
		return key
	}
	id := key[:sep]
	gen, err := strconv.ParseUint(key[sep+1:], 10, 64)
	slot, ok := c.Slots[id]
	if err != nil || !ok || slot.TransportGeneration != gen || key != transportKey(id, gen) {
		return key
	}
	return m.routeKeyLocked(c, id, gen)
}
func (m *Manager) statusLocked(c *Config, id string) RouteStatus {
	s := RouteStatus{State: "direct", SlotID: id, RouteKey: "direct"}
	if id != "" {
		slot, ok := c.Slots[id]
		if !ok {
			s.State = "missing"
			s.RouteKey = id
			return s
		}
		s.Generation = slot.TransportGeneration
		s.RouteKey = m.routeKeyLocked(c, id, s.Generation)
		if !slot.Enabled {
			s.State = "disabled"
			return s
		}
		s.State = "ready"
		if m.observations.Load().unavailable[transportKey(id, s.Generation)] {
			s.State = "unavailable"
			return s
		}
	} else {
		s.RouteKey = m.routeKeyLocked(c, "", 0)
	}
	if until := m.observations.Load().waf[s.RouteKey]; until.After(time.Now()) {
		s.State = "waf_blocked"
		s.RetryAfter = int(math.Ceil(time.Until(until).Seconds()))
	}
	return s
}
func (m *Manager) Status(uid string) RouteStatus {
	c := m.snapshot.Load()
	s := m.statusLocked(c, c.Bindings[uid])
	if c.PendingAccounts[uid] {
		s.State = "pending"
	}
	return s
}
func (m *Manager) Available(uid string) bool {
	s := m.Status(uid)
	return s.State == "direct" || s.State == "ready"
}
func routeError(s RouteStatus) *EgressError {
	code := "proxy_unavailable"
	if s.State == "waf_blocked" {
		code = "proxy_waf_blocked"
	} else if s.State == "pending" {
		code = "proxy_account_transition"
	}
	return &EgressError{Code: code, SlotID: s.SlotID, Generation: s.Generation, Stage: "resolve", RetryAfter: s.RetryAfter}
}
func (m *Manager) ResolveAccount(uid string) (*RouteHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.snapshot.Load()
	if c.PendingAccounts[uid] {
		s := m.statusLocked(c, c.Bindings[uid])
		s.State = "pending"
		return nil, routeError(s)
	}
	h, err := m.resolveLocked(c, c.Bindings[uid], false)
	if h != nil {
		h.accountUID = uid
	}
	return h, err
}
func (m *Manager) ResolveSlot(id string) (*RouteHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resolveLocked(m.snapshot.Load(), id, false)
}
func (m *Manager) resolveLocked(c *Config, id string, probe bool) (*RouteHandle, error) {
	s := m.statusLocked(c, id)
	if probe && (s.State == "unavailable" || s.State == "waf_blocked") {
		if id == "" {
			s.State = "direct"
		} else {
			s.State = "ready"
		}
	}
	if s.State != "direct" && s.State != "ready" {
		return nil, routeError(s)
	}
	key := transportKey(id, s.Generation)
	g := m.transports[key]
	if g == nil {
		g = &generation{transport: m.makeTransport(c.Slots[id])}
		m.transports[key] = g
	}
	g.refs++
	g.callers.Add(1)
	return &RouteHandle{SlotID: id, Generation: s.Generation, RouteKey: s.RouteKey, manager: m, transportKey: key}, nil
}
func (m *Manager) CheckCurrent(h *RouteHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h == nil || h.manager != m || h.released.Load() {
		return &EgressError{Code: "oauth_proxy_changed", Stage: "oauth"}
	}
	c := m.snapshot.Load()
	if h.SlotID != "" {
		s, ok := c.Slots[h.SlotID]
		if !ok || !s.Enabled || s.TransportGeneration != h.Generation {
			return &EgressError{Code: "oauth_proxy_changed", SlotID: h.SlotID, Generation: h.Generation, Stage: "oauth"}
		}
	}
	s := m.statusLocked(c, h.SlotID)
	if s.State != "ready" && s.State != "direct" {
		return routeError(s)
	}
	return nil
}
func (m *Manager) BlockWAF(routeKey string, until time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Serialize alias resolution with probe/config publication. A handle may
	// have been resolved before the successful probe learned its current IP.
	routeKey = m.canonicalRouteKey(m.snapshot.Load(), routeKey)
	if until.After(m.waf[routeKey]) {
		m.waf[routeKey] = until
		m.publishRuntimeLocked()
	}
}
func (m *Manager) CloseIdleConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.transports {
		g.transport.CloseIdleConnections()
	}
}

var _ http.RoundTripper = (*Manager)(nil)

func (m *Manager) publishRuntimeLocked() {
	r := &runtimeState{unavailable: map[string]bool{}, waf: map[string]time.Time{}}
	for k, v := range m.unavailable {
		r.unavailable[k] = v
	}
	for k, v := range m.waf {
		r.waf[k] = v
	}
	m.observations.Store(r)
}
