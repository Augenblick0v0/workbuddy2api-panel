package egress

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func clone(c Config) Config {
	n := c
	n.Slots = make(map[string]Slot, len(c.Slots))
	for k, v := range c.Slots {
		n.Slots[k] = v
	}
	n.Bindings = make(map[string]string, len(c.Bindings))
	for k, v := range c.Bindings {
		n.Bindings[k] = v
	}
	n.PendingAccounts = make(map[string]bool, len(c.PendingAccounts))
	for k, v := range c.PendingAccounts {
		n.PendingAccounts[k] = v
	}
	n.ProbeResults = make(map[string]ProbeResult, len(c.ProbeResults))
	for k, v := range c.ProbeResults {
		n.ProbeResults[k] = v
	}
	n.Operations = make(map[string]json.RawMessage, len(c.Operations))
	for k, v := range c.Operations {
		n.Operations[k] = append(json.RawMessage(nil), v...)
	}
	return n
}
func Open(path string, opts Options) (*Manager, error) {
	m := &Manager{path: path, opts: opts, transports: map[string]*generation{}, accountPools: map[string]string{}, unavailable: map[string]time.Time{}, waf: map[string]time.Time{}}
	if m.opts.FailureCooldown <= 0 {
		m.opts.FailureCooldown = 15 * time.Second
	}
	m.publishRuntimeLocked()
	if opts.BaseTransport == nil {
		m.opts.BaseTransport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		m.opts.BaseTransport = opts.BaseTransport.Clone()
	}
	if opts.Resolver == nil {
		m.opts.Resolver = net.DefaultResolver
	}
	for _, raw := range opts.AllowedCIDRs {
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, &EgressError{Code: "proxy_invalid_config", Stage: "allow_list"}
		}
		m.allowed = append(m.allowed, cidr)
	}
	c := Config{SchemaVersion: 1, NextSlotSeq: 1, Slots: map[string]Slot{}, Bindings: map[string]string{}, ProbeResults: map[string]ProbeResult{}}
	f, err := os.Open(path)
	if err == nil {
		c = Config{}
		info, statErr := f.Stat()
		if statErr != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
			f.Close()
			return nil, &EgressError{Code: "proxy_store_failed", Stage: "permissions"}
		}
		dec := json.NewDecoder(io.LimitReader(f, 4<<20))
		err = dec.Decode(&c)
		if err == nil {
			var extra any
			if e := dec.Decode(&extra); e != io.EOF {
				err = errors.New("extra JSON")
			}
		}
		f.Close()
		if err != nil {
			return nil, &EgressError{Code: "proxy_store_failed", Stage: "read"}
		}
		if err = validate(c); err != nil {
			return nil, &EgressError{Code: "proxy_store_failed", Stage: "validate"}
		}
	} else if !os.IsNotExist(err) {
		return nil, &EgressError{Code: "proxy_store_failed", Stage: "read"}
	}
	c = clone(c)
	m.snapshot.Store(&c)
	return m, nil
}
func (m *Manager) Snapshot() Config { return clone(*m.snapshot.Load()) }
func networkChanged(a, b Slot) bool {
	return a.Enabled != b.Enabled || a.Scheme != b.Scheme || a.Host != b.Host || a.Port != b.Port || a.Username != b.Username || a.Password != b.Password
}
func validate(c Config) error {
	if c.SchemaVersion != 1 || c.NextSlotSeq < 1 || c.Slots == nil || c.Bindings == nil || c.ProbeResults == nil {
		return &EgressError{Code: "proxy_invalid_config", Stage: "schema"}
	}
	for id, s := range c.Slots {
		seq, e := strconv.ParseUint(strings.TrimPrefix(id, "slot-"), 10, 64)
		if !strings.HasPrefix(id, "slot-") || e != nil || seq == 0 || seq >= c.NextSlotSeq || s.ID != id || s.TransportGeneration == 0 || s.Port < 1 || s.Port > 65535 || !ValidProtocol(s.Scheme, s.Username, s.Password) || strings.TrimSpace(s.Host) != s.Host || s.Host == "" || strings.ContainsAny(s.Host, "/@?#\\ \t\r\n") || strings.ContainsAny(s.Username+s.Password, "\r\n") {
			return &EgressError{Code: "proxy_invalid_config", SlotID: id, Stage: "slot"}
		}
		if strings.Contains(s.Host, ":") && net.ParseIP(s.Host) == nil {
			return &EgressError{Code: "proxy_invalid_config", SlotID: id, Stage: "host"}
		}
	}
	return nil
}
func (m *Manager) Update(expected uint64, edit func(*Config) error) (Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.snapshot.Load()
	if expected != old.Revision {
		return Config{}, &EgressError{Code: "revision_conflict", Stage: "store"}
	}
	if old.Revision == ^uint64(0) {
		return Config{}, &EgressError{Code: "proxy_store_failed", Stage: "revision_exhausted"}
	}
	n := clone(*old)
	if err := edit(&n); err != nil {
		return Config{}, err
	}
	if n.SchemaVersion != 1 || n.NextSlotSeq < old.NextSlotSeq {
		return Config{}, &EgressError{Code: "proxy_invalid_config", Stage: "sequence"}
	}
	for id, s := range n.Slots {
		prior, ok := old.Slots[id]
		if !ok {
			seq, _ := strconv.ParseUint(strings.TrimPrefix(id, "slot-"), 10, 64)
			if seq < old.NextSlotSeq {
				return Config{}, &EgressError{Code: "proxy_invalid_config", Stage: "sequence"}
			}
			s.TransportGeneration = 1
		} else {
			s.TransportGeneration = prior.TransportGeneration
			if networkChanged(prior, s) {
				if s.TransportGeneration == ^uint64(0) {
					return Config{}, &EgressError{Code: "proxy_store_failed", Stage: "generation_exhausted"}
				}
				s.TransportGeneration++
			}
		}
		n.Slots[id] = s
	}
	for id := range old.Slots {
		if _, exists := n.Slots[id]; exists {
			continue
		}
		for _, bound := range n.Bindings {
			if bound == id {
				return Config{}, &EgressError{Code: "proxy_in_use", SlotID: id, Stage: "delete"}
			}
		}
		if m.inUseLocked(id) {
			return Config{}, &EgressError{Code: "proxy_in_use", SlotID: id, Stage: "delete"}
		}
	}
	n.Revision = old.Revision + 1
	if err := validate(n); err != nil {
		return Config{}, err
	}
	if err := m.persist(n); err != nil {
		return Config{}, &EgressError{Code: "proxy_store_failed", Stage: "write"}
	}
	// Own an independent copy so a callback retaining n cannot mutate the published snapshot.
	published := clone(n)
	for id, slot := range published.Slots {
		oldKey := m.routeKeyLocked(old, id, slot.TransportGeneration)
		newKey := m.routeKeyLocked(&published, id, slot.TransportGeneration)
		if until := m.waf[oldKey]; until.After(m.waf[newKey]) {
			m.waf[newKey] = until
		}
	}
	if until := m.waf[m.routeKeyLocked(old, "", 0)]; until.After(m.waf[m.routeKeyLocked(&published, "", 0)]) {
		m.waf[m.routeKeyLocked(&published, "", 0)] = until
	}
	m.publishRuntimeLocked()
	m.snapshot.Store(&published)
	for key, g := range m.transports {
		keep := g.slotID == ""
		if g.slotID != "" {
			s, ok := published.Slots[g.slotID]
			keep = ok && s.Enabled && s.TransportGeneration == g.slotGeneration
		}
		if g.accountUID != "" {
			id, bound := published.Bindings[g.accountUID]
			keep = keep && id == g.slotID && bound == g.accountBound
		}
		if !keep || g.retired {
			m.retireTransportLocked(key, g)
		}
	}
	return clone(published), nil
}
func (m *Manager) persist(c Config) error {
	data, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if len(data) > 4<<20 {
		return errors.New("proxy store size limit")
	}
	dir := filepath.Dir(m.path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".proxies-*.tmp")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		if m.opts.StoreHooks != nil && m.opts.StoreHooks.Sync != nil {
			e = m.opts.StoreHooks.Sync(f)
		} else {
			e = f.Sync()
		}
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	// Check directory durability support before the rename commit point. Once
	// rename succeeds the new state is committed and must also be published,
	// even if a later directory sync reports an I/O error.
	var directory *os.File
	if runtime.GOOS != "windows" {
		directory, e = os.Open(dir)
		if e != nil {
			return e
		}
		defer directory.Close()
		if e = m.syncFile(directory); e != nil {
			return e
		}
	}
	rename := os.Rename
	if m.opts.StoreHooks != nil && m.opts.StoreHooks.Rename != nil {
		rename = m.opts.StoreHooks.Rename
	}
	if e = rename(name, m.path); e != nil {
		return e
	}
	if directory != nil {
		// A post-commit directory fsync failure weakens crash durability, not
		// visibility: returning a failed transaction here would leave durable
		// state and the in-memory CAS revision inconsistent.
		_ = m.syncFile(directory)
	}
	return nil
}
func (m *Manager) syncFile(f *os.File) error {
	if m.opts.StoreHooks != nil && m.opts.StoreHooks.Sync != nil {
		return m.opts.StoreHooks.Sync(f)
	}
	return f.Sync()
}
func transportKey(id string, g uint64) string {
	if id == "" {
		return "direct"
	}
	return fmt.Sprintf("%s:%d", id, g)
}
func (m *Manager) inUseLocked(id string) bool {
	for _, g := range m.transports {
		if g.slotID == id && g.callers.Load() > 0 {
			return true
		}
	}
	return false
}
func (m *Manager) InUse(id string) bool { m.mu.Lock(); defer m.mu.Unlock(); return m.inUseLocked(id) }
