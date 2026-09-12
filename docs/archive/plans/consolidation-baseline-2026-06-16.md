# Gate baseline — 2026-06-16 (start of consolidation work)

Measured on this host BEFORE any refactor slice, so "no regression" is checkable.
Run the L2/ssh/transport/gates suites with the venv:
`FILAMENT_TEST_VENV=/root/.claude/jobs/330c2366/tmp/venv/bin/python` (gates.sh +
l2/ssh default to it already; transport-gates needs it exported).

| Check | Command | Baseline |
|-------|---------|----------|
| frontend build | `cd frontend && npx vite build` | PASS (clean) |
| wire char tests | `node frontend/src/net/protocol/__tests__/wire.test.mjs` | PASS |
| wire byte-identity | `node cli/tests/l1a/gate8_byte_identity.mjs` | PASS |
| CLI build | `cd cli && cargo build --release` | PASS (1 pre-existing warning) |
| CLI unit | `cd cli && cargo test --release` | 63/63 PASS |
| transport (QUIC) | `bash cli/tests/transport-gates.sh` | 4/4 PASS |
| ssh-gates | `bash cli/tests/ssh-gates.sh` | 4/4 PASS (charter said 1/4 — that was earlier flakiness) |
| l2-gates | `bash cli/tests/l2-gates.sh` | **4/5** — only gate4 (non-loopback SSRF deny) fails (charter said 3/5) |
| gates.sh core | `SKIP_BROWSER=1 bash cli/tests/gates.sh` | **20/21**, 2 skipped (playwright) — gate18 "quiet-exit G-k" RC=124 timeout |
| holepunch | `bash cli/tests/holepunch-gates.sh` | not yet run (needs netns lab) |

## Known-red analysis (workstream D)

### l2 gate4 — non-loopback SSRF deny  → FIX APPLIED (pending rebuild)
Root cause: the deny LOGIC is correct (non-loopback dial refused, `l2-close`
sent — l2.rs:719). But the operator-facing log line was emitted at `ui::debug`
(main.rs:6464), suppressed at the default Info verbosity, so the gate's
`grep "non-loopback denied" up.log` never matched. The equivalent security
refusal on the shell path (`shell-bootstrap-deny`) uses `ui::say` (Info, visible
by default). Fix: promote the L2 refusal log from `ui::debug` → `ui::say`,
matching the convention. No noise in normal operation (normal initiators always
dial 127.0.0.1; the line only fires on an anomalous/hostile open).

### ssh-gates — green today (4/4)
Charter noted 1/4; that was earlier WebRTC-connection flakiness. Green on a
quiescent host. Watch for flakiness, not a code bug.

### gates.sh gate18 "quiet-exit (G-k)" — timing-flaky, NOT in scope
The transfer completed and verified ("small.bin verified ... acked"); the
receiver then failed to quiet-exit within 120s (RC=124). This is a known
timing-dependent resilience gate (the G-i/G-k glare under churn is tracked as a
product bug, per gates.sh header). Pre-existing; treat as baseline-flaky. Re-run
to confirm it's not a hard regression after any resilience slice.

### Browser gates (13, 16 in gates.sh; gate5/6/12 too) — SKIPPED
Playwright/chromium not installed in `cli/tests`. The dedicated live wire-check
uses `cli/tests/browser-sender.js` / `browser-receiver.js` (separate harness).
