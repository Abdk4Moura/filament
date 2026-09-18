# FILAMENT_ environment variables

The filament CLI reads a small, deliberate set of `FILAMENT_*` environment
variables. Most are escape hatches on top of sensible defaults: the shipped
binary already does the right thing for every documented path, and an env
var is here only when an operator needs to (a) opt into a feature that is
off by default, (b) override a single tunable for a specific deployment or
test, or (c) wire the CLI to a self-hosted signaling server or a different
sshd.

**Most users need none of these.** The two exceptions are `FILAMENT_SERVER`
(point at a self-hosted signaling instance) and `FILAMENT_CONFIG_DIR` (point
at a hermetic config location for testing or a custom install layout). Every
other var has a real, documented default; set it only when that default is
not the right call for your environment.

The variables are split into two tiers:

- **Real knobs** (compiled in every build). These are production operators
  the CLI genuinely honors: turn a feature on or off, raise a timeout for a
  slow network, point at a self-hosted STUN or sshd, pick a config root.
- **Test-only hooks** (compiled only under the `test-hooks` cargo feature;
  stripped from the default and release builds). These exist exclusively to
  drive the resilience gates and fault-injection sims in `cli/tests/`. A
  release build never reads them, and setting them in production is a no-op
  even when the binary does read them, because the surrounding real logic
  is the production path the hook was carved out of. **Must not be set in
  production.**

A third, smaller group is the file-transfer / L2 / ssh tunables
(`FILAMENT_SSH_*`, `FILAMENT_L2_CANDIDATE_SECS`, etc.). These are real, not
test-only, but most installations never touch them: the seamless-ssh path
auto-discovers the right login, port, and host key, and the L2 candidate
budget already has field-tested defaults.

If you only want to read about a specific subsystem, jump to it directly:

- [The transport ladder](#the-transport-ladder)
- [L2 / ssh tunneling](#l2--ssh-tunneling)
- [Warm-link reuse](#warm-link-reuse)
- [Signaling liveness](#signaling-liveness)
- [Faster first connect (DNS race)](#faster-first-connect-dns-race)
- [Clean shutdown](#clean-shutdown)
- [Reference: every / table](#reference-every-variable)

---

## The transport ladder

Filament tries three rungs before falling back to relay, in order, and each
rung is independently gated:

1. **Rung 1: direct QUIC** to a known device, only if
   `FILAMENT_DIRECT=1` (or `FILAMENT_L2=1`, which implies direct for the
   L2/ssh path).
2. **Rung 2: STUN-discovered UDP hole-punch** to a known device, only if
   `FILAMENT_HOLEPUNCH=1`. The peer needs a public IP, the candidate is
   learned by STUN-binding against `FILAMENT_STUN` (or the first `stun:`
   URL in the ICE config).
3. **Rung 3: WebRTC over ICE** (host / srflx / TURN). The always-on default.
   `--relay` forces relay-only ICE; `--no-relay` strips TURN servers entirely
   (the "hard direct-only" promise).

The rungs form a sequential ladder, not a happy-eyeballs race, with rung 1
firing first, rung 2 only if rung 1's host-candidate race misses, and rung
3 catching every case where the rungs above fail. The same label, the same
auth MAC (pair-secret-keyed), and the same `Transport` trait ride every
rung; switching rungs is invisible to the transfer logic. The transport
itself is documented in [`design-direct-cli-transport.md`](design-direct-cli-transport.md)
and [`design-rung2-holepunch.md`](design-rung2-holepunch.md), and the
never-flaky model that hangs the whole ladder together is
[`design/transport-resilience.md`](design/transport-resilience.md).

## L2 / ssh tunneling

`filament netcat`, `filament ssh`, `filament forward`, and `filament pty`
ride the L2 subsystem, which the CLI flips on when any of these conditions
hold:

- `FILAMENT_L2=1` is set, or
- the `up --shell` (or `--shell-only <devices,...>`) policy is in effect, or
- any known device has been granted the `shell` capability (so a plain
  `up` plus `filament grant <dev> shell` works without restarting the
  daemon).

The acceptor side of the L2 path is also where the
[Item 3: direct-first preference for L2](design-l2-direct-ladder.md) lives;
that document spells out the carve-out from the file-transfer hard rule
that `FILAMENT_L2` does *not* also imply a direct default for plain
`filament send`.

The seamless `filament ssh` flow bootstraps over the trusted channel first
(pin host keys, install the managed pubkey under `# BEGIN/END
filament-managed <device>` in the acceptor's `authorized_keys`) and then
hands off to the user's real `ssh` binary, pointed exclusively at
filament-managed material under `$FILAMENT_CONFIG_DIR/ssh/`. The acceptor
returns the login it installed the key into, the initiator pins its real
host public keys, and the ssh process itself never sees a key prompt or a
host-key prompt. The full design is in
[`design-seamless-ssh.md`](design-seamless-ssh.md).

## Warm-link reuse

A long-lived `filament up` daemon exposes a local unix-domain control
socket at `{FILAMENT_CONFIG_DIR}/control.sock`. When a sibling process
(`filament ssh`, `filament netcat`, `filament forward`) needs to reach a
peer that the daemon already holds a live, trusted link to, the sibling
sends a one-line JSON request to the daemon and gets back a raw byte pipe
over a **new L2 stream on the existing link**, skipping signaling,
presence, the direct-QUIC race, and the WebRTC establishment entirely. A
fresh establish happens in roughly a second; the warm path is
sub-millisecond.

The daemon prefers direct links over relay ones for this fast path
("reuse never traps you on a worse path than a fresh dial would pick"),
and the remote acceptor is unchanged: it re-verifies trust per link
regardless of how the L2 stream arrived. Set `FILAMENT_NO_WARM_REUSE=1` to
force every session back onto a fresh establish (useful for debugging
"is this link issue the warm path or the underlying transport?"). This is
a per-process override, not a daemon-only switch.

## Signaling liveness

Long-lived acceptors (`filament up` and `up --shell`) keep a single
socket.io signaling connection open for the daemon's lifetime. A severed
TCP produces no close callback in `rust_socketio`, so the daemon watches
the **inbound-event gap** instead: any socket event (welcome, sync ack,
peer-joined, peer-left, signal, known-peer) bumps a monotonic clock, and
when the gap crosses `FILAMENT_SIGNALING_SILENCE_MS` (default 15 s, well
above the 5 s sync cadence and well below the minute-scale rediscovery
latency an external supervisor would impose), the daemon fires a forced
`sync` heartbeat. A second threshold with no response declares the link
dead and re-dials with exponential backoff, re-announcing presence over
the fresh socket. The `FILAMENT_ACK_TIMEOUT` window is a separate, related
concern on the data plane: the bounded window the sender waits for a
receiver's whole-file `delivery-ack` after the bytes have left, before
failing the send honestly instead of reporting a false "delivered and
verified".

## Faster first connect (DNS race)

Every connect resolves the signaling host before any socket dial. A cold
OS resolver can stall for seconds on a busy or odd-network box, and the
shipped behavior races a fresh OS resolution against a small persisted
cache so a stalling resolver never gates the connect:

- A fresh resolution that answers within `FILAMENT_DNS_RACE_MS` (default
  700 ms) wins, and its IPs are written back to the cache for next time.
- Otherwise the cached IPs are returned immediately; the fresh resolution
  keeps running and refreshes the cache when (if) it lands.
- No cache and a slow resolver: the fresh resolution is awaited for up
  to `FILAMENT_DNS_TIMEOUT_MS` (default 9 s, above the observed worst case
  with headroom), the unavoidable first-ever-connect cost on a cold box.

The cache lives at `{FILAMENT_CONFIG_DIR}/signaling-dns.json`. An IP
literal skips the dance entirely (nothing to resolve or cache). The DNS
racer is the `up` daemon's first-connect hot path: a slow resolver on the
very first call to `{server}/api/whoami` is the difference between an
incoming connect that answers in tens of milliseconds and one that spins
for seconds before the first transport-offer can go out.

## Clean shutdown

A SIGINT or SIGTERM routes a graceful `Ev::Interrupted` through the event
loop AND arms a **signal-owned watchdog** that `std::process::exit`s after
`FILAMENT_SHUTDOWN_GRACE_MS` (default 3 s) regardless of loop state. The
watchdog is the guarantee: a WebRTC `write_data_channel().await` against a
frozen / half-open peer, or a `send_frame` parked on backpressure that
never drains, can wedge the graceful path indefinitely; the watchdog
ensures the process is gone well inside systemd's default `TimeoutStopSec`
(90 s) and that a dropped link is recovered by the resilience layer as an
ordinary disconnect on both ends. `FILAMENT_QUIET_EXIT_SECS` is a
separate, receiver-side window: how long the recv quiet-check must hold
(everything done, nobody attached, no consent questions open) before
exiting without a `peer-left` event, the G-k fallback that fires when a
sender completes a transfer and then vanishes before its leave event is
ever delivered (no `peer-left` to read, so a quiet-exit branch exits the
recv instead of idling to the connect-timeout).

---

## Reference: every variable

Variables are grouped by audience. **Everyday / user-facing** covers what
an operator or self-hosting user might set. **Transport / connectivity**
covers the ladder tunables. **Timeouts and budgets** covers the bounded
windows. **Test-only hooks** covers the fault-injection env vars the gates
use; these are compiled in only under the `test-hooks` cargo feature and
must not be set in production.

A small number of "test-only" vars are not actually under
`#[cfg(feature = "test-hooks")]` in source (`FILAMENT_DIRECT_NO_PUBLIC`,
`FILAMENT_DIRECT_TEST_BLOCK`): they are *only* set by gate scripts, have
no value outside that context, and the production code never branches on
them. They are still listed in the test-only section.

### Everyday / user-facing

| Variable | Values (default) | What it does |
| --- | --- | --- |
| `FILAMENT_SERVER` | URL string (`https://api.filament.autumated.com`) | Signaling server. Honored by clap as the global `--server` flag (set the env, no flag needed); `--server` on the command line wins. The `--server` flag, the `config server` file key, then the built-in default are the precedence order, in the same shape every other filament command follows. |
| `FILAMENT_CONFIG_DIR` | Path (`~/.config/filament` on unix) | Root of the filament config tree: `devices.json`, the managed ssh keypair and known_hosts, the warm-reuse control socket, the DNS cache, and the diag log. Honors hermetic tests; the `home` directory is used when unset. |
| `FILAMENT_NAME` | Display name string (config `name`, else `user@host`) | Display name shown to peers. If `--name` is passed, the CLI exports this env var before the runtime spawns any workers; the resolver in `display_name()` then reads it ahead of the config file and the `$USER@hostname` fallback. |
| `FILAMENT_UID` | String (auto: `cli-<role>-<install_id>-<pid>-<nanos>`) | Pins the per-process signaling `uid` to a fixed value, primarily so the C6 same-uid supersede gate (`main.rs:638`) can exercise the "same device on a new sid" path. The `cli-s-/cli-r-/cli-p-` role prefix is preserved under the override, so the same-role skip (C13) keeps working. Production should leave this unset. |
| `FILAMENT_NO_IMPLICIT_INIT` | `1` (unset) | Restore the pre-U1 precondition: a verb that needs an identity fails fast with "no identity. Run `filament init` first" instead of minting one. Unset (the default), the identity is created silently on first use and one line says so, once (`docs/design-relationship-ux.md` §3.1). Empty and `0` count as unset. |
| `FILAMENT_NONINTERACTIVE` | Any value (unset) | Opt out of the guided interactive code entry from the env. Mirrors `--no-interactive`; any value disables the prompt. A non-TTY stdin always disables the prompt regardless. |
| `FILAMENT_COLOR` | `never` (unset → auto: TTY + not `NO_COLOR` + not `TERM=dumb`) | Force-disable color output when set to `never`. Otherwise the color decision follows the standard `NO_COLOR` + `TERM` checks. |
| `FILAMENT_LOG` | `critical` / `info` / `debug` / `trace` (`info`) | Global verbosity ceiling. Overrides `-v` / `-q` when set; otherwise the flags decide (`-q` is `critical`, `-v` is `debug`, `-vv` is `trace`). `-v` increments the level; `FILAMENT_LOG=trace` is `vv`. The value-prop lines (route label, relay banner) always print. |
| `FILAMENT_SSH_PORT` | Integer (22) | Override the port the `filament ssh` ProxyCommand dials on the peer. Mirrors `FILAMENT_L2_DIALHOST` for the host side. Use this when the peer's sshd is on a non-standard port. |
| `FILAMENT_SSH_USER` | String (the acceptor's reported login, else `$USER`, else `root`) | Login account for the ssh destination. The acceptor's report (the bootstrap-ack `user` field) is authoritative over a local `$USER` guess, which is usually wrong cross-machine (`agboola@laptop` vs `root@server`). Set this env only when you want to override that decision. |
| `FILAMENT_SSH_HOSTKEY` | Path to a pubkey file (prod: `/etc/ssh/ssh_host_*.pub`) | Path to a file holding the acceptor's host public keys, one per line. Production reads the standard `/etc/ssh` directory; the gates point this at a throwaway sshd's pubfile so they never touch the system sshd. |
| `FILAMENT_NO_WARM_REUSE` | `1` (unset → enabled) | Force every `filament ssh` / `netcat` / `forward` back onto a fresh establish instead of riding the `up` daemon's warm link. Per-process; useful for isolating "is this issue the warm path or the underlying transport?". |
| `FILAMENT_BUILD_INFO` | Build-stamp string (set by `build.rs`) | The version string baked into the binary at build time and printed by `filament --version`. Not set by users. |

### Transport / connectivity

| Variable | Values (default) | What it does |
| --- | --- | --- |
| `FILAMENT_DIRECT` | `1` (unset → disabled) | Opt-in to rung 1 of the transport ladder: the direct authenticated-QUIC dial to a known device, no WebRTC, no ICE, no relay tax. The whole rung-1 path is dead unless this is set, and the shipped WebRTC path is byte-for-byte unchanged when it is not. Set this when both peers are CLIs and you want a known-device transfer over the reachable host candidate. |
| `FILAMENT_HOLEPUNCH` | `1` (unset → disabled) | Opt-in to rung 2 of the ladder: the STUN-discovered UDP hole-punch that runs after rung 1's host-candidate race fails. Rung 2 binds its own second raw socket, STUNs it to learn the server-reflexive mapping, and runs rung 1's *unchanged* QUIC handshake over the punched socket. Fails gracefully on symmetric NAT (the punch times out and rung 3 takes over). |
| `FILAMENT_L2` | `1` (unset → disabled) | Turn on the L2/ssh acceptor (`up`/`recv` now serves `l2-open`, `pty-open`, and the seamless `filament ssh` bootstrap). Also implies `FILAMENT_DIRECT` for the L2 path only, per [`design-l2-direct-ladder.md`](design-l2-direct-ladder.md): the L2 use case needs reliable CLI-to-CLI and the file-transfer `FILAMENT_DIRECT` default is deliberately not flipped. |
| `FILAMENT_STUN` | `host:port` (first `stun:` URL in the ICE config) | Override the STUN server the rung-2 punch and the `doctor` probe use to learn a server-reflexive candidate. `host:port` is parsed and resolved; no scheme prefix. STUN failure is graceful (no srflx is advertised, rung 2 simply does not fire for that peer). |
| `FILAMENT_PUBLIC_IP` | IP literal (auto: `{server}/api/whoami`, cached 5 min) | Public IP advertised as a rung-1 direct candidate. Cached for five minutes per server so a stable box does not re-fetch on every connect; the env override always wins and never touches the network. |
| `FILAMENT_DNS_RACE_MS` | Milliseconds (700) | Bounded wait for a fresh OS DNS resolution before the cached IPs are allowed to win the race outright. Comfortably above a healthy resolver's answer and well below the cold-stall ceiling; a healthy box always uses fresh DNS, only a stalling resolver falls back to the cache. |
| `FILAMENT_DNS_TIMEOUT_MS` | Milliseconds (9,000) | Hard cap on the fresh OS resolution itself, so the CLI's own pre-resolve can never hang the process when the cache is empty (first-ever connect from a cold box). Above the observed worst case with headroom. |
| `FILAMENT_WARM_STANDBY` | `1` / `true` / `on` or `0` / `false` / `off` (unset → session-kind default) | Force on or off the warm-redundant transport opt-in. The `up` daemon defaults to ON (long-lived interactive session, the kind a mid-session drop is intolerable for); one-shot `send` defaults to OFF (a single transfer does not justify a second socket and NAT mapping). Use this to flip a sustained `send` into a warm-standby session in a test, or to kill-switch a daemon in production. |
| `FILAMENT_UPGRADE_PROBE` | `0` / `false` / `off` (unset → enabled) | Kill switch for the relay-to-direct auto-upgrade prober (Phase 0 of the never-flaky design, GAP-6). When enabled, a session currently on relay keeps probing for a direct path and seamlessly cuts back the moment a fresh direct standby is verified moving data. The `--no-relay` flag also makes this a no-op. |
| `FILAMENT_UPGRADE_FIRST_MS` | Milliseconds (5,000) | Delay before the first relay-to-direct re-probe after a peer falls to relay. Soon, because the cause is often a transient NAT or path hiccup that heals in seconds. |
| `FILAMENT_UPGRADE_STEADY_MS` | Milliseconds (25,000) | Steady-state re-probe cadence once direct keeps failing. The schedule is first probe at `first_ms`, then each failed probe doubles the interval toward this cap, so a symmetric-NAT peer that will *never* get direct does not get hammered (CPU and battery cost). |
| `FILAMENT_UPGRADE_VERIFY_MS` | Milliseconds (2,500) | Verify-before-upgrade window: once a direct standby connects alongside the live relay link, it must move real data continuously for at least this long before the prober cuts over. Prevents thrash on a flaky direct path that connects then immediately re-stalls. |
| `FILAMENT_UPGRADE_VERIFY_IDLE_MS` | Milliseconds (1,200) | Idle guard inside the verify window: if the direct standby goes idle for this long it is judged regressed and discarded, the prober stays on relay. Tighter than the main `FILAMENT_STALL_MS` so a flaky standby fails fast. |
| `FILAMENT_ADOPT_ACTIVE_MS` | Milliseconds (3,000) | When the same device reappears on a fresh signaling sid (C6 supersede), is the existing data channel still considered "active"? Below this idle threshold, the reconnect is treated as cosmetic and the old link is kept; a frozen-alive peer that has gone past this threshold still gets superseded. 3 s sits well above a healthy sub-100 ms inter-frame gap, so a transient ICE blip cannot masquerade as idle. |

### Timeouts and budgets

| Variable | Values (default) | What it does |
| --- | --- | --- |
| `FILAMENT_L2_CANDIDATE_SECS` | Seconds (7) | Outer wall for the L2 initiator (`filament ssh` / `netcat` / `forward`) from "KnownPeer observed" to "ChannelReady observed". Generous, a slow-but-real ICE lands around 5 s, but the L2 path is not allowed to hang past this on the per-candidate rotation. |
| `FILAMENT_SEND_TIMEOUT` | Seconds (60) | Establish deadline for `filament send`: how long the spinner is allowed to spin waiting for a peer to connect to the offered room, before failing honestly. `0` disables the bound (a long-lived interactive transfer in a tight loop will not cut you off, but an ICE wedge is no longer capped). Once a live data channel opens the bound is disarmed, so big transfers are never interrupted. |
| `FILAMENT_ACK_TIMEOUT` | Seconds (15) | How long the sender waits for the receiver's whole-file `delivery-ack` after every byte has left, before re-probing once (re-sending `file-end` to prompt a possibly-lost ack) and then failing the send honestly if the ack still does not land. The receiver computed a sha256 of every received byte and compared against the sender's offered digest; that ack is the only deterministic "it landed intact" signal. `delivery not confirmed` is the error, never a false "delivered + verified". |
| `FILAMENT_PAIR_GRACE_SECS` | Seconds (60) | Per-candidate budget for the SPAKE2 pairing / ephemeral-ceremony handshake. The first peer whose ceremony confirms becomes the authenticated counterparty; a per-peer budget lets a decoy / wrong-words candidate drop individually without bailing the whole `recv`. The overall backstop (no peer authenticates at all) is the same value. The same knob also bounds the code-path transfer's PAKE confirmation. |
| `FILAMENT_REJOIN_SECS` | Seconds (45) | Blind rejoin window for an unannounced peer departure (C21). Holds the line this long waiting for the peer's client to auto-rejoin (C6 supersede completes the recovery). A peer that announced `brb` (mobile file picker suspends the tab) gets its declared ttl plus slack, not this value. |
| `FILAMENT_QUIET_EXIT_SECS` | Seconds (10) | Receiver-side quiet-check window: how long "everything done, nobody attached, no consent questions open" must hold before the recv exits without a `peer-left` event. The G-k fallback that fires when a sender completes a transfer and then vanishes before its leave event is ever delivered, no `peer-left` to read, so the quiet-exit branch fires instead of idling to the connect-timeout. |
| `FILAMENT_SHUTDOWN_GRACE_MS` | Milliseconds (3,000) | Hard upper bound on shutdown: after SIGINT/SIGTERM, the signal-owned watchdog `std::process::exit`s after this many ms regardless of the event-loop state. `0` is honored (next-tick force-exit). Comfortably under systemd's default `TimeoutStopSec` (90 s) so a wedged `write_data_channel().await` or a `send_frame` parked on backpressure that never drains cannot block exit past the bound. |
| `FILAMENT_STALL_MS` | Milliseconds (6,000) | Bytes-moved stall threshold for the main loop's watchdog (Phase 0, GAP-1). An in-flight transfer whose link's `idle_ms()` exceeds this while the control channel is still alive is declared stalled, and the correction ladder runs. The threshold is on *time since the last byte*, never on throughput, so a slow-but-MOVING link (which keeps stamping activity) never trips, only a frozen one does. 6 s sits well above a slow mobile uplink's inter-chunk gap and well below human patience. |
| `FILAMENT_SIGNALING_SILENCE_MS` | Milliseconds (15,000) | Watchdog for the long-lived acceptor's signaling link: if no inbound socket event and no successful `sync` ack lands for this long, the outer reconnect loop fires a forced `sync` heartbeat, and a second threshold with no response declares the link dead and re-dials. Well above the 5 s sync cadence so a single slow ack never false-trips. |
| `FILAMENT_DOCTOR_PROBE_SECS` | Seconds (30) | Outer wall for `filament doctor` establish-then-drop probes. Generous, a slow-but-real ICE lands around 5 s, but the probe is not allowed to hang past this even when the path is wedged. |

### Test-only hooks (NOT for production)

The variables in this section exist exclusively to drive the resilience
gates and fault-injection sims in `cli/tests/`. A large subset is compiled
in **only** under the `test-hooks` cargo feature
(`cli/Cargo.toml:22-27`), which is **not** in `default` and **not** pulled
by the release profile, so a default `cargo build --release` (what users
install) strips every test hook from the binary, no env reads, no
corruption / freeze / drop injection logic. The build the gates use
(`cargo build --features test-hooks`) is the only build that honors these
vars.

A small number of these (the `FILAMENT_DIRECT_NO_PUBLIC`,
`FILAMENT_DIRECT_TEST_BLOCK`, `FILAMENT_L2_DIALHOST` family) are
*technically* not behind `#[cfg(feature = "test-hooks")]` in source: they
are only ever set by gate scripts, and the production code never branches
on them. They are still listed here because the surrounding real logic is
the production path the hook was carved out of, and they have no purpose
outside a test run.

**Must not be set in production.** Setting these on a release build is a
no-op; setting them on a `test-hooks` build that is running real traffic
will inject the described fault (a frozen data path, a corrupt byte, a
dropped event, a wedged loop).

| Variable | What it does |
| --- | --- |
| `FILAMENT_TEST_PAIR_STALL` | Connect but never send our SPAKE2 element, so the pairing / transfer code-path ceremony budget fires deterministically. The `pair` ceremony's fail-fast guard (no 10-minute orphan). |
| `FILAMENT_TEST_WEBRTC_RELAY_ONLY` | `1` forces every WebRTC link to relay-only ICE, modeling a peer with no direct path (hard NAT) for the relay-fallback auto-escalation gate. Faithful to the "direct can't, relay can" condition auto-fallback exists for. |
| `FILAMENT_TEST_DISABLE_MODEB_DROP` | Reverts the gate-18 mode-B post-completion drop to the old reconnect-always path, so the gate proves the A/B: with the toggle set, a sender that departs after delivering every byte flaps the link forever; with it unset, recv exits cleanly. |
| `FILAMENT_TEST_NO_DEFER` | Reverts the deferred peer-left drop to the unconditional-drop baseline. The C6b / #28 fix: a peer-left on a still-flowing channel is stashed, the live transfer completes on it, and the dropped link is reaped harmlessly. The baseline (this toggle set) strands the sender. |
| `FILAMENT_TEST_INJECT_PEER_LEFT` | Integer (bytes). Once the active peer's transfer has sent at least this many bytes, synthesize a `peer-left` for the active sid without touching the data channel. The deferred-drop path must keep the link and let the transfer finish on it. |
| `FILAMENT_TEST_NO_SIGNALING_RECONNECT` | Reverts the daemon acceptor to the no-outer-loop path, so the signaling-drop gate's A/B baseline can prove the acceptor ZOMBIES without the fix. |
| `FILAMENT_TEST_WEDGE_LOOP` | Once links are live, freeze the event loop forever, faithfully simulating a peer transport whose inline write never returns. With the wedge active, the graceful `Ev::Interrupted` is never processed, only the signal-owned force-exit watchdog can still terminate the process. Proves the A/B for the multi-link shutdown hang. |
| `FILAMENT_TEST_CHURN_AFTER_COMPLETE` | Once the receiver is done, force each surviving link to go stuck repeatedly, reset its attempts (mirroring the real flap's attempts-reset, so `MAX_ATTEMPTS` never caps it) and re-inject `Ev::Stuck`. Baseline (toggle unset) hangs to timeout; fix (toggle set) drops the link and exits cleanly. |
| `FILAMENT_TEST_DROP_FILE_END` | Drop the `file-end` control frame so a fully-received stream is stranded in `by_sid`, mirrors a sender whose PeerConnection tears down before the best-effort file-end is delivered. The G-k completion sweep must then finalize it on size. |
| `FILAMENT_TEST_DROP_PEER_LEFT` | Drop a `peer-left` event so the quiet-exit fallback (G-k) is exercised deterministically. SIGSTOP cannot do it; engine.io's ping timeout reaps a frozen client in ~30 s and the legit peer-left wins the race. |
| `FILAMENT_TEST_SUPPRESS_ACK` | The receiver finalizes the file intact but suppresses the outbound `delivery-ack`, faithfully simulating an ack that never reaches the sender on an otherwise-healthy link (the black-hole-on-the-ack case). The sender must then end UNCONFIRMED, never a false "delivered + verified". Distinct from `CORRUPT_RECV` (which drives the re-request loop): here the bytes are whole, only the ack is withheld. |
| `FILAMENT_TEST_CORRUPT_RECV` | Transfer id. Flips the last on-disk byte of the matching transfer just before its whole-file hash is computed, deterministically inducing the corrupt-receive case so the gate can prove reject + re-fetch. Combine with `FILAMENT_TEST_CORRUPT_ONCE=1` for the auto-recovery path. |
| `FILAMENT_TEST_CORRUPT_ONCE` | `1` makes the corruption inject exactly once (the re-fetch then succeeds), proving auto-recovery. The "already fired" latch is a process-global `AtomicBool` in `test_hooks` (no env mutation; the old code did an unsafe `set_var` of `FILAMENT_TEST_CORRUPT_FIRED` inside the async runtime). |
| `FILAMENT_TEST_CORRUPT_FIRED` | Latch value (process-global, set internally by the `CORRUPT_ONCE` path). No user sets this; the documentation record is for completeness. |
| `FILAMENT_TEST_FREEZE_AFTER_BYTES` | Integer (bytes). The first direct transport's data path goes silently dark after it has written ~N bytes of file data; `send_frame` parks forever while the QUIC connection stays UP and CONTROL frames keep flowing. The exact "open channel, zero data bytes" black-hole (the 0% hang / a NAT rebind that strands only the data 5-tuple), reproduced deterministically. One-shot across the process: once one transport has frozen, a fresh transport built by the correction ladder is *not* frozen, so the test proves the stall is both DETECTED and AUTO-RECOVERED on the re-dialled path, not merely detected. |
| `FILAMENT_TEST_FREEZE_PERSIST` | `1` makes the data-path freeze PERSISTENT instead of one-shot, so every fresh direct transport (including the correction ladder's rung-c re-dials) freezes after the byte threshold. The direct / in-place-repair ladder can never recover; the only way the transfer completes is rung (d) escalation to the TURN relay. How the relay-fallback gate forces the "direct can't, relay can" condition deterministically. |
| `FILAMENT_TEST_DIRECT_UNBLOCK_MS` | Integer (ms). Lifts the persistent direct freeze for any transport born after N ms of process uptime. So the timeline is: early direct transports freeze (the peer falls to relay, rung d), then once the prober dials a fresh direct standby after the unblock moment, that late transport is *not* frozen and carries data, letting the prober verify + upgrade back to direct. Unset means no lift (the freeze persists forever, as `FREEZE_PERSIST` needs). |
| `FILAMENT_TEST_DIRECT_FLAKY` | `1` makes a post-unblock direct standby CONNECT and move a little data, then RE-FREEZE almost immediately, modeling a flaky direct path that comes up but won't hold. The verify-before-upgrade guard must catch this and discard the standby, stay on relay, never flapping relayed-to-direct. With this set, the unblock lift is GRANTED for connection (so the standby forms) but the transport re-freezes after a tiny byte threshold. |
| `FILAMENT_TEST_EMIT_LOSS` | Float in `[0.0, 1.0)` (unset → `0.0`). C30's gate L: drops this fraction of outbound session-state emits (`join`, `subscribe`, `sync`) at random. The convergence tick loop is what must repair the damage. Default 0.0 means no loss; the gate typically sets a non-zero value plus a seed. |
| `FILAMENT_TEST_EMIT_SEED` | Integer (default `0xF11AC30D`). Seeds the xorshift64* PRNG the loss shim uses, so a given loss fraction + seed deterministically drops the same emits across runs. Reproducibility for gate L. |
| `FILAMENT_DIRECT_TEST_BLOCK` | `1` (unset → race runs). Force the rung-1 direct race to fail (simulate a blocked direct path) so the fallback gate can assert WebRTC still completes with the rung-1 flag on. Not a product knob, only the fallback gate sets it. |
| `FILAMENT_DIRECT_NO_PUBLIC` | `1` (unset → public candidate advertised). Suppress rung-1's public (`whoami`) candidate. Models the common NAT class that does not preserve the source port, the class rung-2's STUN-learned srflx exists to catch. Not a product knob, only the hole-punch gate sets it. |
| `FILAMENT_DIRECT_LOOPBACK_ONLY` | `1` (unset → full candidate set). Pin rung-1 candidates to loopback (`127.0.0.1`). A multi-homed host advertises many local candidates and the simultaneous-open race can then pick a pair that cannot actually carry data; this knob makes same-host gates deterministic by advertising only loopback. Compiled in only under the `test-hooks` cargo feature. |
| `FILAMENT_L2_DIALHOST` | Hostname or IP (production: `127.0.0.1`). The dial target the L2 initiator (`netcat` / `ssh` / `forward`) advertises for the `l2-open` control frame. Production is localhost-only (the SSRF defense); the env is a test-only override so the SSRF gate can drive a non-loopback open and observe the acceptor refuse it. |
