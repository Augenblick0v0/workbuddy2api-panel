package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

// Never marshal an egress.Config/Slot directly from management handlers.
type proxySlotDTO struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Enabled      bool                `json:"enabled"`
	Scheme       string              `json:"scheme"`
	Host         string              `json:"host"`
	Port         int                 `json:"port"`
	Username     string              `json:"username"`
	HasPassword  bool                `json:"has_password"`
	Generation   uint64              `json:"transport_generation"`
	BindingCount int                 `json:"binding_count"`
	Probe        *egress.ProbeResult `json:"probe,omitempty"`
}

func (p *Panel) proxyRoutes() {
	for pattern, fn := range map[string]http.HandlerFunc{
		"GET /panel/api/proxies":                 p.proxyList,
		"POST /panel/api/proxies":                p.proxyCreate,
		"PATCH /panel/api/proxies/{id}":          p.proxyPatch,
		"DELETE /panel/api/proxies/{id}":         p.proxyDelete,
		"PUT /panel/api/accounts/{uid}/proxy":    p.proxyBind,
		"DELETE /panel/api/accounts/{uid}/proxy": p.proxyCleanOrphan,
		"POST /panel/api/proxies/assign":         p.proxyAssign,
		"POST /panel/api/proxies/{id}/test":      p.proxyTest,
	} {
		p.mux.HandleFunc(pattern, p.withAuth(p.proxyAdmin(fn)))
	}
}

// A browser write must be same-origin, even if it knows the shared API key.
// Origin-less Bearer requests remain available for scripts. Host is not inferred
// from client-supplied forwarding headers.
func (p *Panel) proxyAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.apiKey() == "" {
			proxyError(w, 503, "proxy_admin_auth_required")
			return
		}
		if p.cfg.Egress == nil {
			proxyError(w, 503, "proxy_not_configured")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
				proxyError(w, 403, "proxy_origin_denied")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, r.Host) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
					proxyError(w, 403, "proxy_origin_denied")
					return
				}
			}
		}
		next(w, r)
	}
}

func proxyError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": code, "code": code})
}

func proxyFailure(w http.ResponseWriter, err error) {
	var ee *egress.EgressError
	if errors.As(err, &ee) {
		if ee.RetryAfter > 0 {
			w.Header().Set("Retry-After", fmt.Sprint(ee.RetryAfter))
		}
		writeJSON(w, egress.HTTPStatus(err), map[string]any{
			"error": ee.Code, "code": ee.Code, "slot_id": ee.SlotID, "generation": ee.Generation, "stage": ee.Stage,
		})
		return
	}
	proxyError(w, 500, "proxy_store_failed")
}

func proxyDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		proxyError(w, 400, "invalid_proxy_request")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		proxyError(w, 400, "invalid_proxy_request")
		return false
	}
	return true
}

func (p *Panel) proxyList(w http.ResponseWriter, r *http.Request) {
	c := p.cfg.Egress.Snapshot()
	counts := map[string]int{}
	for _, id := range c.Bindings {
		counts[id]++
	}
	slots := make([]proxySlotDTO, 0, len(c.Slots))
	for id, s := range c.Slots {
		dto := proxySlotDTO{ID: id, Name: s.Name, Enabled: s.Enabled, Scheme: s.Scheme, Host: s.Host, Port: s.Port, Username: s.Username, HasPassword: s.Password != "", Generation: s.TransportGeneration, BindingCount: counts[id]}
		if probe, ok := c.ProbeResults[id]; ok {
			cp := probe
			dto.Probe = &cp
		}
		slots = append(slots, dto)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].ID < slots[j].ID })
	accounts := map[string]any{}
	known := map[string]bool{}
	if p.cfg.Pool != nil {
		for _, a := range p.cfg.Pool.List() {
			known[a.UID] = true
			id, assigned := c.Bindings[a.UID]
			accounts[a.UID] = map[string]any{"assigned": assigned, "slot_id": id, "route": p.cfg.Egress.Status(a.UID), "orphan": false}
		}
	}
	for uid, id := range c.Bindings {
		if !known[uid] {
			accounts[uid] = map[string]any{"assigned": true, "slot_id": id, "route": p.cfg.Egress.Status(uid), "orphan": true}
		}
	}
	writeJSON(w, 200, map[string]any{"revision": c.Revision, "slots": slots, "accounts": accounts})
}

type proxyEdit struct {
	Revision      *uint64 `json:"revision"`
	OperationID   string  `json:"operation_id,omitempty"`
	Name          *string `json:"name,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
	Scheme        *string `json:"scheme,omitempty"`
	Host          *string `json:"host,omitempty"`
	Port          *int    `json:"port,omitempty"`
	Username      *string `json:"username,omitempty"`
	Password      *string `json:"password,omitempty"`
	ClearPassword bool    `json:"clear_password,omitempty"`
}

func editSlot(s egress.Slot, in proxyEdit) egress.Slot {
	if in.Name != nil {
		s.Name = strings.TrimSpace(*in.Name)
	}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if in.Scheme != nil {
		s.Scheme = *in.Scheme
	}
	if in.Host != nil {
		s.Host = *in.Host
	}
	if in.Port != nil {
		s.Port = *in.Port
	}
	if in.Username != nil {
		s.Username = *in.Username
	}
	if in.Password != nil {
		s.Password = *in.Password
	}
	if in.ClearPassword {
		s.Password = ""
	}
	return s
}

func validProxySlot(s egress.Slot) bool {
	if len(s.Name) > 128 || len(s.Username) > 1024 || len(s.Password) > 4096 {
		return false
	}
	if s.Scheme != "http" && s.Scheme != "https" {
		return false
	}
	if s.Port < 1 || s.Port > 65535 || s.Host == "" || len(s.Host) > 253 || strings.TrimSpace(s.Host) != s.Host {
		return false
	}
	if strings.ContainsAny(s.Host, "/@?#\\\x00\r\n\t ") || strings.ContainsAny(s.Username+s.Password, "\x00\r\n") {
		return false
	}
	if strings.Contains(s.Host, ":") && net.ParseIP(s.Host) == nil {
		return false
	}
	return true
}

type proxyOperation struct {
	Fingerprint string          `json:"fingerprint"`
	Status      int             `json:"status"`
	Result      json.RawMessage `json:"result"`
}

func opFingerprint(kind string, input any) string {
	b, _ := json.Marshal(input)
	h := sha256.Sum256(append([]byte(kind+"\x00"), b...))
	return hex.EncodeToString(h[:])
}

func (p *Panel) replayProxyOp(w http.ResponseWriter, id, fp string) bool {
	if id == "" {
		return false
	}
	if len(id) > 128 {
		proxyError(w, 400, "invalid_operation_id")
		return true
	}
	raw, ok := p.cfg.Egress.Snapshot().Operations[id]
	if !ok {
		return false
	}
	var op proxyOperation
	if json.Unmarshal(raw, &op) != nil {
		proxyError(w, 500, "proxy_store_failed")
		return true
	}
	if op.Fingerprint != fp {
		proxyError(w, 409, "operation_conflict")
		return true
	}
	writeJSON(w, op.Status, op.Result)
	return true
}

func saveProxyOp(c *egress.Config, id, fp string, status int, result any) error {
	if id == "" {
		return nil
	}
	if len(c.Operations) >= 4096 {
		return &egress.EgressError{Code: "operation_limit", Stage: "store"}
	}
	if _, exists := c.Operations[id]; exists {
		return &egress.EgressError{Code: "revision_conflict", Stage: "store"}
	}
	raw, _ := json.Marshal(result)
	op, _ := json.Marshal(proxyOperation{Fingerprint: fp, Status: status, Result: raw})
	if c.Operations == nil {
		c.Operations = map[string]json.RawMessage{}
	}
	c.Operations[id] = op
	return nil
}

func (p *Panel) proxyCreate(w http.ResponseWriter, r *http.Request) {
	var in proxyEdit
	if !proxyDecode(w, r, &in) {
		return
	}
	if in.Revision == nil {
		proxyError(w, 400, "revision_required")
		return
	}
	fp := opFingerprint("create", in)
	if p.replayProxyOp(w, in.OperationID, fp) {
		return
	}
	s := editSlot(egress.Slot{Enabled: true}, in)
	if !validProxySlot(s) {
		proxyError(w, 400, "invalid_proxy_config")
		return
	}
	var result map[string]any
	_, err := p.cfg.Egress.Update(*in.Revision, func(c *egress.Config) error {
		s.ID = fmt.Sprintf("slot-%d", c.NextSlotSeq)
		c.NextSlotSeq++
		s.TransportGeneration = 1
		c.Slots[s.ID] = s
		result = map[string]any{"ok": true, "id": s.ID, "revision": c.Revision + 1}
		return saveProxyOp(c, in.OperationID, fp, 201, result)
	})
	if err != nil {
		if p.replayProxyOp(w, in.OperationID, fp) {
			return
		}
		proxyFailure(w, err)
		return
	}
	writeJSON(w, 201, result)
}

func (p *Panel) proxyPatch(w http.ResponseWriter, r *http.Request) {
	var in proxyEdit
	if !proxyDecode(w, r, &in) {
		return
	}
	if in.Revision == nil {
		proxyError(w, 400, "revision_required")
		return
	}
	id := r.PathValue("id")
	var apiErr string
	c, err := p.cfg.Egress.Update(*in.Revision, func(c *egress.Config) error {
		s, exists := c.Slots[id]
		if !exists {
			apiErr = "proxy_not_found"
			return errors.New(apiErr)
		}
		s = editSlot(s, in)
		if !validProxySlot(s) {
			apiErr = "invalid_proxy_config"
			return errors.New(apiErr)
		}
		c.Slots[id] = s
		return nil
	})
	if apiErr != "" {
		status := 400
		if apiErr == "proxy_not_found" {
			status = 404
		}
		proxyError(w, status, apiErr)
		return
	}
	if err != nil {
		proxyFailure(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "revision": c.Revision})
}

func (p *Panel) proxyDelete(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Revision *uint64 `json:"revision"`
	}
	if !proxyDecode(w, r, &in) {
		return
	}
	if in.Revision == nil {
		proxyError(w, 400, "revision_required")
		return
	}
	id := r.PathValue("id")
	var apiErr string
	c, err := p.cfg.Egress.Update(*in.Revision, func(c *egress.Config) error {
		if _, exists := c.Slots[id]; !exists {
			apiErr = "proxy_not_found"
			return errors.New(apiErr)
		}
		for _, bound := range c.Bindings {
			if bound == id {
				apiErr = "proxy_in_use"
				return errors.New(apiErr)
			}
		}
		delete(c.Slots, id)
		delete(c.ProbeResults, id)
		return nil
	})
	if apiErr != "" {
		status := 409
		if apiErr == "proxy_not_found" {
			status = 404
		}
		proxyError(w, status, apiErr)
		return
	}
	if err != nil {
		proxyFailure(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "revision": c.Revision})
}

func (p *Panel) proxyBind(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Revision *uint64 `json:"revision"`
		SlotID   *string `json:"slot_id"`
	}
	if !proxyDecode(w, r, &in) {
		return
	}
	if in.Revision == nil || in.SlotID == nil {
		proxyError(w, 400, "revision_and_slot_required")
		return
	}
	uid := r.PathValue("uid")
	if !validUID(uid) || p.cfg.Pool == nil || p.cfg.Pool.AuthByUID(uid) == nil {
		proxyError(w, 404, "account_not_found")
		return
	}
	current := p.cfg.Egress.Snapshot()
	if id, exists := current.Bindings[uid]; exists && id == *in.SlotID {
		writeJSON(w, 200, map[string]any{"ok": true, "revision": current.Revision})
		return
	}
	var apiErr string
	c, err := p.cfg.Egress.Update(*in.Revision, func(c *egress.Config) error {
		if *in.SlotID != "" {
			s, exists := c.Slots[*in.SlotID]
			if !exists {
				apiErr = "proxy_not_found"
				return errors.New(apiErr)
			}
			if !s.Enabled {
				apiErr = "proxy_disabled"
				return errors.New(apiErr)
			}
		}
		c.Bindings[uid] = *in.SlotID
		return nil
	})
	if apiErr != "" {
		status := 409
		if apiErr == "proxy_not_found" {
			status = 404
		}
		proxyError(w, status, apiErr)
		return
	}
	if err != nil {
		proxyFailure(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "revision": c.Revision})
}

func (p *Panel) proxyCleanOrphan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Revision *uint64 `json:"revision"`
		Confirm  bool    `json:"confirm"`
	}
	if !proxyDecode(w, r, &in) {
		return
	}
	if in.Revision == nil || !in.Confirm {
		proxyError(w, 400, "orphan_cleanup_confirmation_required")
		return
	}
	uid := r.PathValue("uid")
	if !validUID(uid) {
		proxyError(w, 400, "invalid_uid")
		return
	}
	if p.cfg.Pool != nil && p.cfg.Pool.AuthByUID(uid) != nil {
		proxyError(w, 409, "account_still_present")
		return
	}
	c, err := p.cfg.Egress.Update(*in.Revision, func(c *egress.Config) error {
		delete(c.Bindings, uid)
		return nil
	})
	if err != nil {
		proxyFailure(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "revision": c.Revision})
}

type proxyAssignRequest struct {
	Preview          bool              `json:"preview"`
	Realm            string            `json:"realm,omitempty"`
	UIDs             []string          `json:"uids,omitempty"`
	ExpectedRevision *uint64           `json:"expected_revision"`
	OperationID      string            `json:"operation_id,omitempty"`
	Assignments      map[string]string `json:"assignments,omitempty"`
}

func (p *Panel) assignment(c egress.Config, in proxyAssignRequest) (map[string]string, map[string]string) {
	eligible := []string{}
	skipped := map[string]string{}
	selected := map[string]bool{}
	for _, uid := range in.UIDs {
		selected[uid] = true
	}
	for _, a := range p.cfg.Pool.List() {
		if len(selected) > 0 && !selected[a.UID] {
			continue
		}
		if in.Realm != "" && a.Realm != in.Realm {
			continue
		}
		if _, ok := c.Bindings[a.UID]; ok {
			skipped[a.UID] = "already_assigned"
			continue
		}
		if a.Disabled || a.Paused {
			skipped[a.UID] = "account_disabled_or_paused"
			continue
		}
		eligible = append(eligible, a.UID)
	}
	ids := []string{}
	for id, s := range c.Slots {
		if s.Enabled {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	sort.Strings(eligible)
	out := map[string]string{}
	for i, uid := range eligible {
		if len(ids) == 0 {
			skipped[uid] = "no_enabled_slots"
			continue
		}
		out[uid] = ids[i%len(ids)]
	}
	return out, skipped
}

func (p *Panel) proxyAssign(w http.ResponseWriter, r *http.Request) {
	var in proxyAssignRequest
	if !proxyDecode(w, r, &in) {
		return
	}
	if in.ExpectedRevision == nil || (in.Realm != "" && in.Realm != "cn" && in.Realm != "global") || len(in.UIDs) > 10000 {
		proxyError(w, 400, "invalid_assignment")
		return
	}
	if p.cfg.Pool == nil {
		proxyError(w, 503, "pool_unavailable")
		return
	}
	fp := opFingerprint("assign", in)
	if !in.Preview && p.replayProxyOp(w, in.OperationID, fp) {
		return
	}
	snap := p.cfg.Egress.Snapshot()
	if snap.Revision != *in.ExpectedRevision {
		proxyError(w, 409, "revision_conflict")
		return
	}
	assignments, skipped := p.assignment(snap, in)
	if in.Preview {
		writeJSON(w, 200, map[string]any{"revision": snap.Revision, "assignments": assignments, "skipped": skipped})
		return
	}
	if in.Assignments != nil && !reflect.DeepEqual(in.Assignments, assignments) {
		proxyError(w, 409, "assignment_changed")
		return
	}
	var result map[string]any
	_, err := p.cfg.Egress.Update(*in.ExpectedRevision, func(c *egress.Config) error {
		for uid, id := range assignments {
			c.Bindings[uid] = id
		}
		result = map[string]any{"ok": true, "revision": c.Revision + 1, "assignments": assignments, "skipped": skipped}
		return saveProxyOp(c, in.OperationID, fp, 200, result)
	})
	if err != nil {
		if p.replayProxyOp(w, in.OperationID, fp) {
			return
		}
		proxyFailure(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (p *Panel) proxyTest(w http.ResponseWriter, r *http.Request) {
	// No target URL or account credential may be accepted from a caller.
	var in struct {
		Generation *uint64 `json:"generation,omitempty"`
	}
	if !proxyDecode(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	s, exists := p.cfg.Egress.Snapshot().Slots[id]
	if !exists {
		proxyError(w, 404, "proxy_not_found")
		return
	}
	if in.Generation != nil && *in.Generation != s.TransportGeneration {
		proxyError(w, 409, "revision_conflict")
		return
	}
	result, err := p.cfg.Egress.Probe(r.Context(), id)
	if err != nil {
		var ee *egress.EgressError
		code := "proxy_probe_failed"
		if errors.As(err, &ee) {
			code = ee.Code
		}
		writeJSON(w, 200, map[string]any{"ok": false, "result": result, "error": code, "code": code})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "result": result})
}
