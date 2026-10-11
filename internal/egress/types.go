// Package egress owns durable account routes and fail-closed outbound transports.
// Its snapshots contain secrets and must never be serialized to management APIs.
package egress

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Slot struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Enabled             bool   `json:"enabled"`
	Scheme              string `json:"scheme"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	Username            string `json:"username,omitempty"`
	Password            string `json:"password,omitempty"`
	TransportGeneration uint64 `json:"transport_generation"`
}
type ProbeResult struct {
	SlotID       string    `json:"slot_id"`
	Generation   uint64    `json:"generation"`
	IP           string    `json:"ip,omitempty"`
	LatencyMS    int64     `json:"latency_ms"`
	CheckedAt    time.Time `json:"probed_at"`
	SuccessfulAt time.Time `json:"last_success_at,omitempty"`
	Status       string    `json:"status"`
	ErrorCode    string    `json:"error_code,omitempty"`
}
type Config struct {
	SchemaVersion int                        `json:"schema_version"`
	Revision      uint64                     `json:"revision"`
	NextSlotSeq   uint64                     `json:"next_slot_seq"`
	Slots         map[string]Slot            `json:"slots"`
	Bindings      map[string]string          `json:"bindings"`
	ProbeResults  map[string]ProbeResult     `json:"probe_results"`
	Operations    map[string]json.RawMessage `json:"operations,omitempty"`
}
type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// StoreHooks injects filesystem failures in local tests only; never expose through management APIs.
type StoreHooks struct {
	Rename func(string, string) error
	Sync   func(*os.File) error
}
type Options struct {
	StoreHooks    *StoreHooks
	BaseTransport *http.Transport
	AllowedCIDRs  []string
	ProbeURL      string
	Resolver      Resolver
}
type EgressError struct {
	Code       string `json:"code"`
	SlotID     string `json:"slot_id,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	Stage      string `json:"stage,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
	Sent       bool   `json:"sent"`
}

func (e *EgressError) Error() string { return "egress: " + e.Code }
func HTTPStatus(err error) int {
	var e *EgressError
	if !errors.As(err, &e) {
		return 502
	}
	switch e.Code {
	case "revision_conflict", "oauth_proxy_changed", "proxy_in_use", "operation_limit":
		return 409
	case "proxy_store_failed":
		return 500
	case "proxy_unavailable", "proxy_waf_blocked", "proxy_route_required":
		return 503
	case "proxy_timeout", "upstream_timeout":
		return 504
	case "proxy_invalid_config":
		return 400
	default:
		return 502
	}
}

type RouteStatus struct {
	State      string `json:"state"`
	SlotID     string `json:"slot_id,omitempty"`
	RouteKey   string `json:"route_key"`
	Generation uint64 `json:"generation"`
	RetryAfter int    `json:"retry_after,omitempty"`
}
type generation struct {
	transport *http.Transport
	refs      int
	callers   atomic.Int64
	retired   bool
}
type RouteHandle struct {
	SlotID       string
	Generation   uint64
	RouteKey     string
	manager      *Manager
	transportKey string
	release      sync.Once
	released     atomic.Bool
}

func (h *RouteHandle) Release() {
	if h == nil || h.manager == nil {
		return
	}
	h.release.Do(func() { h.released.Store(true); h.manager.releaseRef(h.transportKey, true) })
}

type routeContextKey struct{}

func WithRoute(ctx context.Context, h *RouteHandle) context.Context {
	return context.WithValue(ctx, routeContextKey{}, h)
}

type runtimeState struct {
	unavailable map[string]bool
	waf         map[string]time.Time
}
type Manager struct {
	observations atomic.Pointer[runtimeState]
	mu           sync.Mutex
	path         string
	opts         Options
	snapshot     atomic.Pointer[Config]
	allowed      []*net.IPNet
	transports   map[string]*generation
	unavailable  map[string]bool
	waf          map[string]time.Time
}
