# Development evidence

Status: **开发完成，生产未发布**. T01–T05 passed on2026-10-11 Asia/Hong_Kong.
T06 requires separate approval; T07 deferred.

## T01 — 2026-10-11 Asia/Hong_Kong

- Target was absent. Initial full clone stalled; terminated only its identified git processes,
  then fetched the exact commit with `--depth=1` in the new isolated repository.
- `git rev-parse HEAD`: `d66384d9e3d69655f799d7d8f2e5fba1946e00ab`.
- Branch: `feature/account-proxy`. Hub read-only HEAD: `5c353c841221ef1b85e7091ef48b789c51dd8c06`.
- `git diff --no-index` internal tree against the source snapshot: no content differences.
- No AGENTS.md/CONTEXT.md found inside the repository; README and LICENSE inspected.
- Actual outbound sends re-searched, inventory matches the plan evidence.
- Production read-only SSH recheck: same HEAD, empty git status, image
  `sha256:2b0dc00a5607675582cbca0b49c7674fea38a0aac9e80e914c7bd4d7912e81b1`,
  user `10001:10001`, network `workbuddy2api-panel_default`, state running.
  Same auths/data/config mounts; no proxy environment keys. Image has Compose labels,
  no embedded commit label: source/artifact provenance still needs T06 verification.
- No production data/config/credentials copied; no production changes or restart.
- Windows Go 1.26.5. Baseline test initially failed at dependency download through
  proxy.golang.org (connection timeout), not a test assertion.
- Per-command `GOPROXY=https://goproxy.cn,direct` (no dependency upgrade):
  `go test ./internal/upstream -run 'TestNewChatClientNoTotalTimeoutAndSharedTransport|TestChatStreamRoutesToChatHTTP|TestChatHTTPNilFallsBackToHTTP' -count=1`
  PASS: `ok .../internal/upstream 1.007s`.
- Docker executable present but engine initially absent; WSL Ubuntu-22.04 available,
  no Linux Go initially installed. Linux Go1.23 environment is being prepared.

## Final acceptance requirements

T01–T05 passed; production business/proxy/release acceptance remains T06.
No early full test/build, no ordinary-source hash gates, no repeated successful baseline test.

## T02

- Core and API incremental negative checks first failed at missing implementations, then passed.
- `go test ./internal/egress ./internal/panel -run 'TestProxy|TestEgress' -count=1` PASS:
  egress 0.408s; panel 1.025s.
- Real counting proxy/CONNECT tests cover 407, disconnected proxy, explicit CIDR,
  trusted/untrusted TLS proxy certificates, Basic credentials and upstream header isolation.
- Store tests cover restart, stable IDs, explicit direct, concurrent CAS, corrupt/missing
  schema rejection and injected file fsync/rename failures. POSIX existing secret store
  permissions broader than 0600 fail closed. Runtime availability uses immutable atomic reads.
- Generation channel barrier: established old stream survives edits, new send uses new
  generation, stale handle rejected, retired generation released on body close.
- Probe bounded/fixed target, old-generation result rejection, shared-known-IP WAF isolation.
- Controller tests: empty-key503/missing-key401/cross-origin403, secret DTO checks,
  password preserve/clear, disabled binding retention, revision409, bound deletion409,
  assignment preview preserves explicit direct/paused, concurrent operation replay/restart,
  retained orphan cleanup with explicit confirmation, no reused slot IDs.
- Added orphan cleanup: `DELETE /panel/api/accounts/{uid}/proxy` requires revision and
  `confirm:true`; rejects accounts still present. No automatic orphan removal.
- Linux Go1.23.12 prepared in WSL Ubuntu-22.04. Local Docker engine27.5.1 started;
  no production service operation. In-app browser bootstrap failed; isolated Playwright CLI
  Chrome session opened successfully for later real UI acceptance.
- Storage rename is the commit point: temp-file fsync and directory support check precede
  rename; a post-commit directory-sync error does not report an uncommitted write or leave
  disk/memory inconsistent. Postcommit power-loss durability has this explicit filesystem
  limitation. File-sync/rename failures before commit keep previous disk and snapshot.

## T03 / T04 integrated

- T03 and T04 used separate worktrees; root integrated T03 `5d2cf12` before T04 `e999241`.
- Root owns OAuth and main/config integration. Auth extension is runtime-only credential
  epoch plus in-place replacement, preserving identity/path/device and blocking stale refresh
  writers. Approved bounded session Peek helper preserves blocked sticky failure semantics.
- Account matrix tests cover25 actual API entrypoints ×A/B counting proxies. Fault tests
  cover407, disconnected/cut-body proxy, uncertain POST no replay, no account punishment,
  sticky/fallback filtering, equal/different known-IP WAF, HeaderTimeout each generation,
  existing SSE surviving edits, public models.dev isolation and redirect rejection.
- OAuth tests coverstate/token/account + CN checkin/balance under pinned route, single-flight,
  cached completion, pending/terminal distinction, generation/disabled/cancel, binding-first
  persistence, both write-failure orderings, preserved credentials before rebind confirmation.
- UI Node behavior16/16 PASS, JS syntax PASS. Includes stale known IP + successful timestamp
  distinct from latest attempt, dirty forms, CAS, CRUD/binding/preview/orphan and OAuth races.
- Integrated prescribed targeted command PASS on Windows Go1.26.5:
  `go test ./internal/upstream ./internal/panel ./internal/server ./internal/pool ./internal/session ./cmd/server -count=1`
  upstream1.711s / panel5.998s / server11.406s / pool0.429s / session1.288s / cmd/server2.139s.
- At the T03/T04 milestone, full ./..., Linux/race/build and real UI were still pending;
  these subsequently passed under T05 below.

## T05 — final acceptance

Final product-source commit: `136d5ec` (documentation-only commits may follow).
Candidate: `workbuddy2api-panel:account-proxy-candidate`.
Final image: `sha256:059b05991cf3165a2644d9c5d12ec71aac6880c7bd8784060c0d1f490cd702ab`.

### One independent combined review

One read-only specialist/final review found3P1, noP0. Root integrated fixes:

1. Late WAF after probe rekey: canonical same-generation keys + merge threshold hits/windows.
2. Stale failed refresh after OAuth replacement: epoch check on every failure exit.
3. Existing UID credential-write failure after binding: durable pending_accounts guard,
   old resolved handles blocked, restart remains blocked, successful OAuth finalization unlocks.

Explicit regression barriers/sequencing tests passed. Also restored existing confirmed500
idempotent billing retries with one pinned route; uncertain failures stop without replay.
No further independent review loop or dual specification/quality agents.

### Linux Go1.23.12

- `go test ./... -count=1`: PASS. Final delivery log:
  `output/playwright/linux-go123-test-delivery.log` (scheduler14.320s, server9.543s).
- `go vet ./...`: PASS at final integrated Go state before the logging-only change.
  Changed egress package subsequently passed `go vet ./internal/egress`; all other Go
  source was unchanged, so duplicate full vet was skipped.
- `CGO_ENABLED=1 go test -race ./internal/egress ./internal/upstream ./internal/panel ./internal/server ./internal/pool -count=1`:
  PASS (1.288/1.719/4.223/11.878/1.187s). After typed logging changed only egress,
  its race suite passed again1.248s; unchanged four packages were not redundantly rerun.
- Windows Node JS syntax + behavior16/16 PASS. Linux lacks Node and corresponding
  existing JS smoke tests skip; actual Node behavior and real Chrome acceptance supply
  that distinct evidence. Interactive fixture test is opt-in, not a silent UI substitute.

### Candidate build and actual container E2E

- Final Docker build PASS with Go1.23 builder; server/login/signin/credit built.
  `output/playwright/docker-build-delivery.log`.
- `scripts/verify-proxy-candidate.ps1`: PASS on final image. Unique local Docker network,
  volume and containers; synthetic global enterprise account and counting fake proxy,
  no exposed upstream ports, no internet forwarding or production credentials.
- Actual candidate `/v1/chat/completions`, balance, refresh, token persistence and
  restart binding restoration PASS. Proxy counter11 / direct counter0.
  Interrupted proxy returns502; existing account remains enabled and unpenalized.
- Final result: `output/playwright/candidate-6baa368e/result.json`;
  raw run: `output/playwright/candidate-runtime-delivery.log`.
- Fixture containers/networks/volumes cleaned up; candidate image retained locally.

### Real browser / visual verdict

- In-app bootstrap failed; isolated Playwright CLI Chrome used, not a simulated DOM
  screenshot. Real slot creation, dirty editing through polling, fault probe, binding
  confirmation and OAuth selection/completion were exercised. OAuth state/token/account/
  initial maintenance counted at B; no direct hits. Never opened the synthetic auth URL.
- Mobile review found vertical navigation/title squeezing; fixed within the existing
  design, then reloaded the real page. Final viewport/document widths390/390 and1440/1440.
  Navigation labels and title nowrap; only the navigation strip scrolls horizontally.
- Root visually inspected exact-size screenshots:
  `output/playwright/desktop-1440x900.png`,
  `output/playwright/mobile-390x844.png`,
  `output/playwright/mobile-editor-390x844.png`.
  Labels/readability/CTA and modal controls accepted; no new page horizontal overflow.
  Password field empty in editor, no password reflected into page/localStorage.
- Older interactive run also recorded OAuth success as new bound UID, A1/B4/direct0:
  `output/playwright/ui-counts-before-layout-fix.json`. Final layout-only run A1/direct0.
  Current browser console had no JS exceptions, only an existing autocomplete suggestion.
- UI fixture stopped cleanly, test PASS731.844s; isolated browser session closed.

### Real failures preserved, not hidden

- Baseline dependency download initially timed out; per-command Go module mirror resolved it.
- Initial race attempt stopped before tests because CGO/compiler was absent. Ephemeral
  Alpine attempts encountered package-network and login-shell PATH failures. Local WSL
  GCC/libc development prerequisites installed; the required Linux race suite then passed.
- BuildKit frontend token fetch failed before compilation. Classic Docker builder with
  already-pulled same Go1.23/Alpine bases built successfully; no dependency/model fallback.
- First runtime fixture assumed restart ready after750ms; corrected bounded readiness/
  asynchronous keepalive waits and dynamic published-port rediscovery.
- Proxy shutdown can yield an already-sent HTTP EOF, correctly reported as uncertain
  upstream_transport_failed rather than fabricated proxy attribution. Fixture now accepts
  that stable stopped-request error while still hard-asserting direct0 and no punishment.
- Full tests/builds were concentrated at T05. Final UI/diagnostic changes caused justified
  final reruns; no same-state successful baseline repeats, no per-task full lint/E2E gates,
  no ordinary-source or repeated hash checks. Image ID is artifact identity, not a hash gate.

### Remaining boundaries / risk

No knownP0/P1 remains after fixes and final verification. Production was only read in T01:
no deployment/restart/data/config/token or colocated-service change. Real production proxy,
management-entry isolation and approved release/rollback exercise remain T06 gates.
Single-process writes only; post-rename directory fsync is best-effort as documented.
CLI/SOCKS/discovery remain T07 deferred. Do not run no-proxy old binaries against bound
accounts; preserve latest tokens/data on any future release rollback.
