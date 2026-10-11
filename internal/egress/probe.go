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

const defaultProbeURL = "https://api.ipify.org?format=json"

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
	if target == "" {
		target = defaultProbeURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	start := time.Now()
	result := ProbeResult{SlotID: id, Generation: h.Generation, CheckedAt: start.UTC(), Status: "error"}
	if err == nil {
		client := &http.Client{Transport: m, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		var res *http.Response
		res, err = client.Do(req)
		if err == nil {
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				err = &EgressError{Code: "proxy_probe_failed", SlotID: id, Generation: h.Generation, Stage: "probe_status"}
			} else {
				var raw []byte
				raw, err = io.ReadAll(io.LimitReader(res.Body, (16<<10)+1))
				if err == nil && len(raw) > 16<<10 {
					err = &EgressError{Code: "proxy_probe_failed", Stage: "probe_size"}
				}
				if err == nil {
					ip := strings.TrimSpace(string(raw))
					var obj struct {
						IP string `json:"ip"`
					}
					if json.Unmarshal(raw, &obj) == nil && obj.IP != "" {
						ip = obj.IP
					}
					parsed := net.ParseIP(strings.TrimSpace(ip))
					if parsed == nil {
						err = &EgressError{Code: "proxy_probe_failed", Stage: "probe_ip"}
					} else {
						result.IP = parsed.String()
						result.Status = "ok"
						result.SuccessfulAt = result.CheckedAt
					}
				}
			}
		}
	}
	result.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		result.ErrorCode = "proxy_probe_failed"
		var ee *EgressError
		if errors.As(err, &ee) {
			result.ErrorCode = ee.Code
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
		if result.IP == "" {
			if old, ok := snap.ProbeResults[id]; ok && old.Generation == h.Generation {
				result.IP = old.IP
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
		return result, &EgressError{Code: result.ErrorCode, SlotID: id, Generation: h.Generation, Stage: "probe"}
	}
	m.mu.Lock()
	delete(m.unavailable, h.transportKey)
	m.publishRuntimeLocked()
	m.mu.Unlock()
	return result, nil
}
