# Account proxy implementation contract

Baseline: Panel `d66384d9e3d69655f799d7d8f2e5fba1946e00ab` (1.13.0-panel).
Branch: `feature/account-proxy`. Hub reference only: `5c353c841221ef1b85e7091ef48b789c51dd8c06`.
Read-only snapshots remain untouched. No production configuration or credentials are used.
The authoritative functional contract is sections 3, 5, 6 of
`D:\codex\.agentdocs\workflow\261011-panel-account-proxy-plan.md`.

## Batches and risk

T01 baseline/environment: low risk, three existing upstream client seam tests.
T02 storage/transport/API: high risk, local filesystem and counting HTTP/CONNECT fixtures.
T03 outbound/OAuth/WAF: high risk, complete outbound matrix, fail-closed and concurrency fixtures.
T04 UI: medium risk, behavior tests and existing panel tests.
T05: integrated review, Linux Go1.23 test/vet/race, Docker four binaries, real browser desktop/mobile.
One integrated specialist review, not per-task dual review.
T06 production release requires separate approval; T07 CLI/discovery deferred.
The 2026-10-11 diagnostics/SOCKS increment is specified in
`D:\codex\.agentdocs\workflow\261011-panel-proxy-diagnostics-socks-plan.md`.
SOCKS uses a small bounded handshake over stdlib net/context rather than
Transport's detached native SOCKS dial: the original request context closes a
canceled handshake socket, and its hook/deadline is removed before connection reuse.
Plain HTTP IP observations are display-only; `verified_ip` preserves the trusted WAF identity.

## T02 interfaces (root-owned integration contract)

`internal/egress` depends only on the standard library, never Pool/auth/server.

```go
type Config struct {
    SchemaVersion int `json:"schema_version"`
    Revision uint64 `json:"revision"`
    NextSlotSeq uint64 `json:"next_slot_seq"`
    Slots map[string]Slot `json:"slots"`
    Bindings map[string]string `json:"bindings"`
    PendingAccounts map[string]bool `json:"pending_accounts,omitempty"`
    ProbeResults map[string]ProbeResult `json:"probe_results"`
}
// Slot: ID, Name, Enabled, Scheme, Host, Port, Username, Password, TransportGeneration.
// Slot.Password is private to persistence: JSON management endpoints use SlotDTO.
type Options struct {
    BaseTransport *http.Transport
    AllowedCIDRs []string // explicit private network allow-list, never enables metadata/link-local
    ProbeURL string // test injection only; no HTTP API parameter
}
func Open(path string, opts Options) (*Manager, error)
func (m *Manager) Snapshot() Config // deep copy; never expose it as management JSON
func (m *Manager) Update(expected uint64, edit func(*Config) error) (Config, error)
func (m *Manager) ResolveAccount(uid string) (*RouteHandle, error)
func (m *Manager) ResolveSlot(id string) (*RouteHandle, error) // empty ID = explicit direct
func (m *Manager) Available(uid string) bool // memory-only; no I/O
func (m *Manager) Status(uid string) RouteStatus
func (m *Manager) CheckCurrent(h *RouteHandle) error // OAuth slot/generation check
func (m *Manager) BlockWAF(routeKey string, until time.Time)
func (m *Manager) CanonicalRouteKey(routeKey string) string
func (m *Manager) Probe(ctx context.Context, id string) (ProbeResult, error)
func (m *Manager) RoundTrip(req *http.Request) (*http.Response, error)
func (m *Manager) CloseIdleConnections()
func WithRoute(ctx context.Context, h *RouteHandle) context.Context
// RouteHandle: SlotID string, Generation uint64, RouteKey string, Release() idempotent.
// RouteStatus: State, SlotID, RouteKey string; Generation uint64; RetryAfter int.
// EgressError: Code, SlotID, Stage string; Generation uint64; RetryAfter int; Sent bool.
// EgressError.Error() must be constant/sanitized; no raw url.Error in public/log paths.
func HTTPStatus(err error) int
```

Storage: schema 1, monotonic IDs and revisions, serial CAS, temp+fsync+rename before publishing;
missing bindings differ from explicit empty/direct. Corrupt existing files stop startup.
Config mutations automatically advance transport generation only on network changes;
name/probe/binding edits do not churn transports. Old streams finish before retirement.
Resolve acquires a caller reference; RoundTrip acquires its own body-lifetime reference.
OAuth retains one handle and must CheckCurrent before every stage.
Account requests resolve once per HTTP send, never infer routing from headers/tokens.
Manager.RoundTrip requires explicit route context; missing marker fails locally.
All redirects are disabled for account/OAuth/probe clients to prevent credential rerouting.
Direct uses Proxy=nil regardless of environment. HTTP/HTTPS proxies validate DNS at dial time.
RPC and SSE use one manager/transport generation with distinct client timeouts.

Store API controllers use Update for atomic create/edit/delete/bind/assignment.
Operation idempotency must survive process restart (persist results in an optional operations map).
Delete rejects bound slots and slots held by OAuth. Bindings of removed accounts remain orphans.
Known equal successful probe IPs share WAF buckets. Probes do not clear active WAF blocks.
Private CIDR allow-list is startup configuration, never supplied by arbitrary management requests.
Additional test-only options: Resolver and StoreHooks (Sync/Rename); none exposed by HTTP.
Manager.InUse guards OAuth slot deletion; Update performs this guard atomically itself,
so edit callbacks must not call Manager methods. Status/Available use atomic snapshots.
PendingAccounts is a durable credential-transition guard: OAuth sets it with binding,
clears it only after successful credential persistence and matching final route commit.
Existing and new UIDs remain blocked across restart on failure; even an account handle
resolved before the guard is rechecked at RoundTrip. Pre-identity ResolveSlot handles remain
separate for OAuth. A pending route returns503 `proxy_account_transition`.
CanonicalRouteKey merges unknown same-generation slot keys into newly learned IP buckets;
historical known IPs and retired generations never alias onto an unrelated new exit.
The refresh credential epoch suppresses both stale successful writes and stale failure
responses after re-login. Existing idempotent billing retries retain one pinned route;
confirmed upstream500 policy stays intact, uncertain transport/body errors never replay.

## Outbound inventory

Account scoped: client.go RefreshToken, ChatStreamContext, enterprise models, v3 config;
global_models; global_register (countries/status/region); profile; billing/report/trial;
travel/growth; tasks/claims; school/events; desktop/events/theme/market/expert chat.
OAuth state/token/account is separately scoped before UID exists.
Public models.dev is isolated from account transport. Redis remains infrastructure.
Independent cmd/login, cmd/signin, cmd/credit and Python/shell scripts are deferred.

## Release/rollback boundary

No production mutation, restart or deployment in T01–T05. Preserve auths/data/config,
cooldown/usage/tasks and live patches. Never touch colocated NewAPI/Sub2API/9Router.
Old no-proxy binaries must not receive bound-account traffic after rollback.
Retain latest post-release tokens/data; rollback artifacts only unless separately validated.
