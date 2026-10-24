package egress

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const defaultProbeURL = "http://api.ipify.org?format=json"
const defaultProbeHTTPSURL = "https://api.ipify.org?format=json"

// WorkBuddy reachability legs. The route only has to reach the realm's own
// site; any HTTP answer (401/403/404 included, e.g. a WAF page) proves the
// proxy tunnels to WorkBuddy, while ipify is unreachable from many China
// exits that serve real traffic fine.
const defaultWBCNTarget = "https://copilot.tencent.com/"
const defaultWBGlobalTarget = "https://www.workbuddy.ai/"

// probeIP only sends credential-free requests to an internally chosen target.
// Its timeout is separate from the overall probe budget, so an HTTP-only failure
// cannot consume the whole budget before the HTTPS check.
func (m *Manager) probeIP(ctx context.Context, target string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", &EgressError{Code: "proxy_probe_failed", Stage: "probe_request"}
	}
	client := &http.Client{Transport: m, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", &EgressError{Code: "proxy_timeout", Stage: "probe", Reason: "deadline"}
		}
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", &EgressError{Code: "proxy_probe_failed", Stage: "probe_status", Reason: "target_http_status"}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (16<<10)+1))
	if err != nil {
		if ctx.Err() != nil {
			return "", &EgressError{Code: "proxy_timeout", Stage: "probe_body", Reason: "deadline"}
		}
		return "", &EgressError{Code: "proxy_probe_failed", Stage: "probe_body"}
	}
	if len(raw) > 16<<10 {
		return "", &EgressError{Code: "proxy_probe_failed", Stage: "probe_size"}
	}
	ip := strings.TrimSpace(string(raw))
	var obj struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.IP != "" {
		ip = obj.IP
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", &EgressError{Code: "proxy_probe_failed", Stage: "probe_ip"}
	}
	return parsed.String(), nil
}

// probeReach sends one credential-free GET and treats any HTTP answer as
// reachable. Unlike probeIP it parses no body and never fails on status.
func (m *Manager) probeReach(ctx context.Context, target string) (WBTargetResult, error) {
	start := time.Now()
	res := WBTargetResult{URL: target, Status: "error"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		res.ErrorCode = "proxy_probe_failed"
		return res, &EgressError{Code: "proxy_probe_failed", Stage: "wb_reach"}
	}
	client := &http.Client{Transport: m, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Do(req)
	if err != nil {
		code := "proxy_probe_failed"
		if ctx.Err() != nil {
			code = "proxy_timeout"
		}
		res.ErrorCode = code
		return res, &EgressError{Code: code, Stage: "wb_reach", Reason: "deadline"}
	}
	defer r.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4<<10))
	res.Status = "ok"
	res.HTTPStatus = r.StatusCode
	res.LatencyMS = time.Since(start).Milliseconds()
	return res, nil
}

// Probe is intentionally a credential-free, fixed-target GET; callers cannot
// provide a URL, headers, token, redirect policy, timeout, or response limit.
// realms (optional, "cn"/"global") narrows the WorkBuddy reachability legs of
// a workbuddy-mode probe to the realms bound to the slot; empty means both.
func (m *Manager) Probe(ctx context.Context, id string, realms ...string) (ProbeResult, error) {
	m.mu.Lock()
	h, err := m.resolveLocked(m.snapshot.Load(), id, true)
	m.mu.Unlock()
	if err != nil {
		return ProbeResult{}, err
	}
	defer h.Release()
	if m.opts.ProbeMode == "" || m.opts.ProbeMode == "workbuddy" {
		return m.probeWorkBuddy(ctx, id, h, realms)
	}
	return m.probeLegacy(ctx, id, h)
}

// probeLegacy is the exit-IP gate of earlier versions: the slot is only
// healthy when a fixed IP-echo target answers 200 with a parseable IP.
func (m *Manager) probeLegacy(ctx context.Context, id string, h *RouteHandle) (ProbeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = context.WithValue(WithRoute(ctx, h), probeContextKey{}, true)
	target := m.opts.ProbeURL
	secureTarget := m.opts.ProbeHTTPSURL
	if target == "" {
		target = defaultProbeURL
		if secureTarget == "" {
			secureTarget = defaultProbeHTTPSURL
		}
	}
	start := time.Now()
	result := ProbeResult{SlotID: id, Generation: h.Generation, CheckedAt: start.UTC(), Status: "error"}
	var err error
	result.IP, err = m.probeIP(ctx, target)
	result.IPStatus = "error"
	if err == nil {
		result.IPStatus = "ok"
		result.IPCheckedAt = result.CheckedAt
	}
	if secureTarget != "" {
		var secureIP string
		secureIP, err = m.probeIP(ctx, secureTarget)
		result.HTTPSStatus = "error"
		if err == nil {
			result.HTTPSStatus = "ok"
			result.IPStatus = "ok"
			result.IP = secureIP
			result.IPCheckedAt = result.CheckedAt
		}
	}
	if err == nil {
		result.Status = "ok"
		result.SuccessfulAt = result.CheckedAt
		result.VerifiedIP = result.IP
	}
	result.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		result.ErrorCode = "proxy_probe_failed"
		var ee *EgressError
		if errors.As(err, &ee) {
			result.ErrorCode = ee.Code
			result.ErrorStage = ee.Stage
			result.ErrorReason = ee.Reason
			result.ProxyStatus = ee.ProxyStatus
		}
		if ctx.Err() != nil {
			result.ErrorCode = "proxy_timeout"
		}
	}
	return m.finishProbe(ctx, id, h, result, err)
}

// probeWorkBuddy gates the slot on WorkBuddy reachability: the exit only has
// to reach the realm's own site with any HTTP answer. The exit-IP lookup is
// kept as an informational field and never fails the probe on its own.
func (m *Manager) probeWorkBuddy(ctx context.Context, id string, h *RouteHandle, realms []string) (ProbeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ctx = context.WithValue(WithRoute(ctx, h), probeContextKey{}, true)
	want := map[string]bool{}
	for _, realm := range realms {
		if realm == "cn" || realm == "global" {
			want[realm] = true
		}
	}
	if len(want) == 0 {
		want["cn"] = true
		want["global"] = true
	}
	start := time.Now()
	result := ProbeResult{SlotID: id, Generation: h.Generation, CheckedAt: start.UTC(), Status: "error"}
	var gate error
	for _, realm := range []string{"cn", "global"} {
		if !want[realm] {
			continue
		}
		target := m.opts.WBCNTarget
		if realm == "global" {
			target = m.opts.WBGlobalTarget
		}
		if target == "" {
			target = defaultWBCNTarget
			if realm == "global" {
				target = defaultWBGlobalTarget
			}
		}
		legCtx, legCancel := context.WithTimeout(ctx, 6*time.Second)
		leg, legErr := m.probeReach(legCtx, target)
		legCancel()
		leg.Realm = realm
		result.WBTargets = append(result.WBTargets, leg)
		if legErr != nil && gate == nil {
			gate = legErr
		}
	}
	// Informational exit-IP lookup; its failures never gate this probe.
	ipTarget := m.opts.ProbeURL
	ipSecureTarget := m.opts.ProbeHTTPSURL
	if ipTarget == "" {
		ipTarget = defaultProbeURL
		if ipSecureTarget == "" {
			ipSecureTarget = defaultProbeHTTPSURL
		}
	}
	result.IPStatus = "error"
	if ip, ipErr := m.probeIP(ctx, ipTarget); ipErr == nil {
		result.IP = ip
		result.IPStatus = "ok"
		result.IPCheckedAt = result.CheckedAt
	}
	if ipSecureTarget != "" {
		result.HTTPSStatus = "error"
		if secureIP, secureErr := m.probeIP(ctx, ipSecureTarget); secureErr == nil {
			result.HTTPSStatus = "ok"
			result.IPStatus = "ok"
			result.IP = secureIP
			result.IPCheckedAt = result.CheckedAt
		}
	}
	if gate == nil {
		result.Status = "ok"
		result.SuccessfulAt = result.CheckedAt
		result.VerifiedIP = result.IP
	}
	result.LatencyMS = time.Since(start).Milliseconds()
	if gate != nil {
		result.ErrorCode = "proxy_probe_failed"
		var ee *EgressError
		if errors.As(gate, &ee) {
			ee.Reason = firstFailedRealm(result.WBTargets)
			gate = ee
			result.ErrorCode = ee.Code
			result.ErrorStage = ee.Stage
			result.ErrorReason = ee.Reason
		}
		if ctx.Err() != nil {
			result.ErrorCode = "proxy_timeout"
		}
	}
	return m.finishProbe(ctx, id, h, result, gate)
}

// firstFailedRealm names the leg that gated the probe for diagnostics.
func firstFailedRealm(legs []WBTargetResult) string {
	for _, leg := range legs {
		if leg.Status != "ok" {
			return leg.Realm
		}
	}
	return ""
}

// finishProbe merges the fresh result with the stored one (keeping historical
// IP observations when the current lookup learned nothing), persists it, and
// clears a transport-fault pause only on a gated success.
func (m *Manager) finishProbe(ctx context.Context, id string, h *RouteHandle, result ProbeResult, err error) (ProbeResult, error) {
	for {
		snap := m.Snapshot()
		if id != "" {
			slot, ok := snap.Slots[id]
			if !ok || !slot.Enabled || slot.TransportGeneration != h.Generation {
				return result, &EgressError{Code: "oauth_proxy_changed", SlotID: id, Generation: h.Generation, Stage: "probe_generation"}
			}
		}
		if old, ok := snap.ProbeResults[id]; ok && old.Generation == h.Generation {
			if result.VerifiedIP == "" {
				result.VerifiedIP = routeIP(old)
			}
			if result.IP == "" {
				result.IP = old.IP
				result.IPCheckedAt = old.IPCheckedAt
			}
			if result.SuccessfulAt.IsZero() {
				result.SuccessfulAt = old.SuccessfulAt
				if result.SuccessfulAt.IsZero() && old.Status == "ok" {
					result.SuccessfulAt = old.CheckedAt
				}
			}
		}
		_, saveErr := m.Update(snap.Revision, func(c *Config) error {
			if id != "" {
				slot, ok := c.Slots[id]
				if !ok || !slot.Enabled || slot.TransportGeneration != h.Generation {
					return &EgressError{Code: "oauth_proxy_changed", SlotID: id, Generation: h.Generation, Stage: "probe_generation"}
				}
			}
			c.ProbeResults[id] = result
			return nil
		})
		if saveErr != nil {
			var ee *EgressError
			if errors.As(saveErr, &ee) && ee.Code == "revision_conflict" {
				continue
			}
			return result, saveErr
		}
		break
	}
	if err != nil {
		// A fixed public probe may be rejected while the actual business host
		// remains reachable through this proxy. Preserve diagnostic failure,
		// but only real account/OAuth traffic can mark the route unavailable.
		return result, &EgressError{Code: result.ErrorCode, SlotID: id, Generation: h.Generation, Stage: result.ErrorStage, Reason: result.ErrorReason, ProxyStatus: result.ProxyStatus}
	}
	m.mu.Lock()
	delete(m.unavailable, h.transportKey)
	m.publishRuntimeLocked()
	m.mu.Unlock()
	return result, nil
}
