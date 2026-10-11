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

// Probe is intentionally a credential-free, fixed-target GET; callers cannot
// provide a URL, headers, token, redirect policy, timeout, or response limit.
func (m *Manager) Probe(ctx context.Context, id string) (ProbeResult, error) {
	m.mu.Lock()
	h, err := m.resolveLocked(m.snapshot.Load(), id, true)
	m.mu.Unlock()
	if err != nil {
		return ProbeResult{}, err
	}
	defer h.Release()
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
		m.markUnavailable(h)
		return result, &EgressError{Code: result.ErrorCode, SlotID: id, Generation: h.Generation, Stage: result.ErrorStage, Reason: result.ErrorReason, ProxyStatus: result.ProxyStatus}
	}
	m.mu.Lock()
	delete(m.unavailable, h.transportKey)
	m.publishRuntimeLocked()
	m.mu.Unlock()
	return result, nil
}
