# Coverage ledger: user-facing flows x platforms

The answer to "what is untested on Windows" (and macOS), without reading every
file. Every user-facing flow crossed with every CI platform, and what today
exercises it.

This is the ledger the ratchet will later enforce: a cell that is empty must be
DECLARED with a reason, and the count of declared-empty cells may only go down.
Version 1 lists what EXISTS today and declares the gaps as they stand. The
enforcement test is designed at the bottom but intentionally NOT built yet:
its flow inventory must match the porting decisions, which come after review.

## Platforms

The three CI runners in `capability-ci.yml` (the only workflow that runs a
behavioural suite on all three): `ubuntu-latest`, `macos-latest`,
`windows-latest`. `test.yml` runs `cargo test` on ubuntu + windows only.

## Cell status vocabulary

- `GREEN` - a test runs this flow on this platform in CI and passes.
- `WIRED` - a test runs this flow on this platform in CI (state as observed).
- `SKIP` - a test exists but is cfg'd out / early-returns on this platform.
  Counts as a DECLARED GAP.
- `IGNORED` - `#[ignore]`, only runs with `--ignored`. DECLARED GAP.
- `RED` - a test runs and currently fails (unclassified until attributed).
- `NOWHERE` - a script/test exists but NO workflow runs it. Not coverage.
- `NO` - no test at all.
- `PENDING` - test exists in an open PR (`#200` on `test/user-flows-caps`).
- `BROKEN` - the PRODUCT path is broken on this platform (issue cited), so no
  test can be green until the product is fixed.

## The matrix

### Start

| flow | ubuntu | macos | windows |
|---|---|---|---|
| `init` (identity + first device) | GREEN (harness inits) | GREEN | GREEN (harness inits) |
| first-run wizard / autostart message | GREEN | GREEN | BROKEN (#204 daemon_alive reads /proc: "started the receiver" always prints failure) |
| `add` mint + claim (PAKE) | GREEN (live_pair) | GREEN | GREEN |
| `add --for device/person` (bounded mint) | PENDING (#200) | PENDING | PENDING |
| `join` (claim, enrollment link) | RED (#212) | RED (#212) | RED (#212) |
| `join` token handling (expired / pre-0.8.4 / cap-store invariant) | PENDING (#200) | PENDING | PENDING |
| `id` | NO | NO | NO |

### Share

| flow | ubuntu | macos | windows |
|---|---|---|---|
| `send <file>` one-time code | GREEN (smoke, direct_blocked) | GREEN | GREEN |
| `receive <code>` | GREEN (smoke, direct_blocked) | GREEN | GREEN |
| byte transparency (CR+LF + binary sweep) | GREEN (smoke) | GREEN | GREEN |
| direct-blocked WebRTC fallback (first contact) | GREEN (direct_blocked) | GREEN | GREEN |
| `send --to` remembered device (daemon peer) | PENDING/RED (#214) | PENDING/RED | PENDING/RED |
| `receive` nearby-network / auto-room | NO | NO | NO |
| `shell <device>` native PTY | GREEN (pty_one_shot_exec_smoke) | GREEN | GREEN |
| `shell --ssh` | BROKEN (0.8.5 netcat ProxyCommand) | BROKEN | BROKEN |
| `reach` | NO | NO | NO |
| `forward` / `--socks` | NO | NO | NO |
| `expose` | NO | NO | NO |
| `mount` | PARTIAL (build + unit only) | PARTIAL | PARTIAL (NameEscaper unit; gate script NOWHERE) |

### Serve

| flow | ubuntu | macos | windows |
|---|---|---|---|
| `up` attached daemon runs | GREEN (spawn_daemon_inner) | GREEN | GREEN |
| daemon WebRTC links | RED (#212/#214 harness artifact) | RED | RED |
| `up --install` autostart | NO | NO | BROKEN (#204, #205 ctl) |
| `up --detach` | NO | NO | BROKEN (#215 log, #204 poll) |
| `down` | NO | NO | BROKEN (#204 never finds daemon) |
| `logs` | NO | NO | BROKEN (#215 nothing writes daemon.log) |
| `reset` | NO | NO | NO |
| settings get/set/unset | NO | NO | NO |

### Devices

| flow | ubuntu | macos | windows |
|---|---|---|---|
| `devices` list | WIRED (devices_status_tests, test.yml) | NO | WIRED (devices_status_tests) |
| `grant` / `revoke` | GREEN (revoked cells; rig sc_02 Linux) | WIRED | WIRED |
| revoked device first operation denied | GREEN (revoked_device_first_transfer) | GREEN | GREEN |
| revoked + direct-blocked fallback denied | PENDING/RED (#214) | PENDING/RED | PENDING/RED |
| `requests` | NO | NO | NO |

### Mesh / platform plumbing

| flow | ubuntu | macos | windows |
|---|---|---|---|
| `addr` | NO | NO | NO |
| `doctor` | WIRED (doctor.rs units) | NO | WIRED (doctor.rs units) |
| platform-conditional code budget | WIRED (surface_platform ratchet, test.yml) | NO | WIRED |
| bare-print budget | WIRED (surface_output ratchet, test.yml) | NO | WIRED |

### Web (browser half, new-renewer's slice)

| flow | ubuntu | macos | windows |
|---|---|---|---|
| browser send / receive / add | NOWHERE (Playwright scripts, no workflow) | NOWHERE | NOWHERE |
| QR / launcher | NO | NO | NO |

### Presentation (gallery, experiments/ux)

| flow | ubuntu | macos | windows |
|---|---|---|---|
| asciinema gallery | WIRED (run.sh, Linux) | NO | NO (deliberately: presentation only, not assertions) |

## Declared gaps (grandfathered today, count only goes down)

Cell count today: the empty / declared cells above. Each is either declared
above with an issue number, or is genuinely NO and must gain a test or a
declared reason. The rule, once the ratchet lands: a NEW empty cell fails the
ratchet; an existing one is grandfathered ONLY with a reason line here.

Top of the list by cost to a release:
1. The `--relay` harness artifact (#212/#214): every harness daemon runs
   `up --relay`, so daemon-peer WebRTC links cannot establish in the rig. This
   blocks the JOIN and SEND-TO cells on all three platforms. The ledger's most
   valuable empty cells are downstream of this single configuration line.
2. Windows serve lifecycle (`up --install`, `up --detach`, `down`, `logs`):
   all BROKEN by #204/#205/#215, so no test can be green until the product
   fixes them. These are the "nobody knew" cells from last week.
3. `reach`, `forward`, `expose`, `receive` nearby-network, `requests`,
   settings, `id`, `addr`: NO tests on any platform.
4. `mount` integration gate exists as `mount-gates.sh` but runs NOWHERE.
5. Web browser half exists as Playwright scripts but runs NOWHERE.
6. `shell --ssh` BROKEN by the 0.8.5 netcat ProxyCommand gap (shipped finding).

## Blocker note: why the join + send-to cells cannot be green today

`capability_harness.rs` spawns every daemon with `up --relay`
(capability_harness.rs:435). `--relay` sets `Conn.relay_only` (main.rs:6006,
6415), and every WebRTC link built by that daemon uses
`RTCIceTransportPolicy::Relay` (main.rs:8279, net.rs:1261). The harness backend
serves STUN-only ICE config (backend/config.py DEFAULT_ICE, no FIL_TURN_HOST),
so a relay-only peer gathers ZERO candidates. Any flow whose peer is a harness
daemon therefore cannot establish: `join` (issuer daemon) and `send --to`
(remembered daemon peer, the revocation control). The passing siblings
(`pair_and_transfer_smoke`, `direct_blocked_falls_back_to_webrtc_promptly`)
never involve a daemon: both ends are one-shot `send`/`receive` without
`--relay`, so they gather host candidates and connect. Full diagnosis in the
#212/#214 report (pending verification build). The glare in #214 is a symptom
of the same churn plus mixed role functions (uid-based `polite_role` on the
daemon side vs sid-based `polite_role_legacy` on the one-shot side).

## Ratchet design (to build AFTER porting decisions)

A `cli/tests/coverage_ledger.rs` modeled on `surface_platform.rs`: a `flows()`
table of every flow x platform, a `declared()` table of grandfathered empty
cells (each with a reason), and a test that FAILS when (a) a flow is not
listed, or (b) a cell that has a test on any platform has none on another
without a `declared()` entry. The count of undeclared empty cells must never
increase. Same shape as the two existing ratchets: grandfather today, only go
down, delete a red-on-arrival test rather than pay it.

Open question for review: how does the ratchet know a flow "has a test" on a
platform at build time? Options: (a) a static table maintained by hand next to
the test definitions (cheap, can rot), (b) the harness's own CI run reports
which `#[test]`s executed per platform and the ratchet consumes that (more
honest, one workflow away). Recommend (b) fed from `capability-ci.yml`, since
(a) is exactly the "declared in a comment, enforced nowhere" shape this repo
has learned to stop trusting.
