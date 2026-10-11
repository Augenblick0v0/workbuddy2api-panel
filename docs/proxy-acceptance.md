# Development evidence

Status: development incomplete; production not released. T06 requires separate approval; T07 deferred.

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

T01 and T02 are implemented; T03–T05 remain pending.
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
