package egress

import (
	"math"
	"net/http"
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
	if p, ok := c.ProbeResults[id]; ok && p.Generation == g && p.IP != "" {
		return "ip:" + p.IP
	}
	return transportKey(id, g)
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
	return m.statusLocked(c, c.Bindings[uid])
}
func (m *Manager) Available(uid string) bool {
	s := m.Status(uid)
	return s.State == "direct" || s.State == "ready"
}
func routeError(s RouteStatus) *EgressError {
	code := "proxy_unavailable"
	if s.State == "waf_blocked" {
		code = "proxy_waf_blocked"
	}
	return &EgressError{Code: code, SlotID: s.SlotID, Generation: s.Generation, Stage: "resolve", RetryAfter: s.RetryAfter}
}
func (m *Manager) ResolveAccount(uid string) (*RouteHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.snapshot.Load()
	return m.resolveLocked(c, c.Bindings[uid], false)
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
