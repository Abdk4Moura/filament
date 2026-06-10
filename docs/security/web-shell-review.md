# Web-Shell Security Review

**Feature:** "web-shell" — a browser opens an interactive PTY (login shell) on a
device running `filament up --shell`, carried over a WebRTC data channel (or a
direct-QUIC link), gated by a pairing proof plus a `shell` capability grant.

**Scope reviewed:** `cli/src/l2.rs`, `cli/src/main.rs` (the L2/PTY/pair-proof/
direct paths), `cli/src/direct.rs` (direct-QUIC auth), `cli/src/sshkeys.rs`
(authorized_keys install), `frontend/src/lib/webrtc.js`, `frontend/src/ui/WebTerminal.jsx`.

**Branch:** `transport-direct-quic`. **Mode:** read-only defensive review of the
author's own pre-release code. No code was modified.

---

## Executive summary

The gating is **structurally sound**. On both transport paths the `trusted` flag
that unlocks the PTY can only be set after a cryptographic identity check bound to
the channel: the WebRTC pair-proof is bound to the **sorted DTLS fingerprints**
(`proof_for`, main.rs:727), and the direct-QUIC link is born trusted only after a
**channel-bound HMAC over RFC-5705 keying material** passes (`authenticate`,
direct.rs:349–377). A non-verified peer is denied a PTY and every other L2 stream.
The SSRF/loopback restriction holds. The self-connect guard is present on both the
dial and accept sides.

The residual findings are **post-authentication** weaknesses (a peer that already
holds the `shell` cap) and **hardening gaps**, not gate bypasses. The two that
should be fixed before shipping a public terminal are the **unbounded PTY/stream
resource exhaustion** (no concurrency cap, `pty_resizers` leak) and the
**multi-line pubkey injection** in `shell-bootstrap`. The **root-by-default PTY
with no privilege-drop** is an accepted-risk that must be documented loudly.

**Findings:** Critical 0 · High 1 · Medium 4 · Low 4

---

## 1. Trust boundary — can a non-verified peer get a PTY or L2 stream?

**No.** Traced end-to-end on both paths.

### WebRTC pair-proof path
- A `Link` is created with `trusted: false` (main.rs:1889).
- `trusted = true` is assigned in exactly **one** place on this path: the
  `pair-proof` handler (main.rs:4384), and only when
  `proof_for(secret, peer_uid, peer_uid, my_uid, my_fp, their_fp) == mac`
  (main.rs:4380) for some known device. The fingerprints come from the live
  peer connection (main.rs:4363–4367); if they aren't known yet the proof is
  ignored (main.rs:4367–4370).
- Every web-shell entry point re-reads `l.trusted` at handling time:
  - `pty-open` gate: `trusted && (auto_allows || device_allows)` (main.rs:4231–4237).
  - `l2-open` gate: `accept_control(&v, trusted)` → denies if `!trusted`
    (l2.rs:397–399).
  - `shell-bootstrap` gate: same `trusted && …` (main.rs:4165–4169).
- A `pty-open`/`l2-open` arriving **before** the proof simply sees
  `trusted == false` and is refused — there is no early-accept window.

### Direct-QUIC pre-trust path (`adopt_direct`)
- The acceptor only starts a direct race for a peer it matched by **presence
  channel of a specific known secret** (`KnownPeer`, main.rs:3099–3108) — i.e.
  it commits to one device's secret up front.
- `start_direct` → `on_transport_offer` runs `race_connect` with **that one
  secret** (main.rs:2032, 2043). `authenticate` exchanges an HMAC tag over the
  QUIC exporter keying material and rejects on mismatch (direct.rs:372–375).
- Only on the authenticated winner does `Ev::DirectReady` fire and
  `adopt_direct` create a `Link { trusted: true, verified_name: Some(name), … }`
  (main.rs:2107–2110). The `verified_name` is the matched petname — exactly the
  cap-store key the PTY gate uses.
- The comment block at l2.rs:746–755 documents the deliberate decision that the
  direct link is "born trusted" because the pair-secret MAC already proved
  identity; the DTLS pair-proof is intentionally skipped (a QUIC link has no
  DTLS fingerprints). This is correct: the QUIC MAC is itself channel-bound.

**Verdict:** a peer that is not pair-proof-verified (WebRTC) or not
QUIC-MAC-authenticated (direct) cannot obtain a PTY or any L2 stream.

---

## 2. Capability gate — bypassable? does `--shell` over-grant?

The gate is `trusted && (shell_policy.auto_allows(name) || device_allows(name,"shell"))`,
evaluated identically for `shell-bootstrap` (main.rs:4165) and `pty-open`
(main.rs:4233). The name used is `verified_name` (the proven petname, main.rs:4161,
4232), **not** the spoofable presence display name — correct.

- **Default policy `Granted`:** `auto_allows` returns `false` (main.rs:817), so
  only devices with the `shell` cap in `devices.json` pass. `device_allows`
  is deny-by-default for non-`transfer` caps (main.rs:616–621). The per-device
  `shell` cap **is** honored under the default policy. Good.
- **`--shell` (policy `All`):** `auto_allows` returns `true` for **every paired
  device** (main.rs:818). This is an intentional convenience flag, but it is a
  **broad over-grant**: it hands a root shell (see §6) to *all* current and
  *future* paired devices, including any device introduced later via
  `pair-intro` (main.rs:4409). See **Finding M-2**.
- **`--shell-only a,b`:** scoped to the named set (main.rs:819). Good — this is
  the safer way to express the same intent and should be the documented default.

No bypass of the gate itself was found.

---

## 3. Broadcasting the `caps`/`shell` hint — info leak?

`{ "type": "caps", "shell": l2_enabled }` is sent to a peer on `ChannelReady`
(main.rs:4066) and only flips a UI button (`peerShell`, webrtc.js:387–389). It is
sent **only after** a data channel exists, i.e. to a peer that already reached this
host. It reveals one bit ("this host can offer a terminal") to any peer that
connects — including, briefly, a not-yet-verified WebRTC peer, since the actual
gate is server-side. This is **not a secret** and leaks no credential or target
information; the design comment correctly notes the real gate is enforced
server-side regardless of the hint. **Acceptable** (Low — see L-3 for the minor
recommendation to defer it until trusted).

---

## 4. Self-connect guard `is_self_uid` — complete on both sides?

The original concern: pair secrets are symmetric, so a same-host process can pass
the pair-proof and tunnel a caller into the **local** daemon's sshd instead of the
intended remote (`netcat pop2` served by the wrong host). The guard:

```rust
fn is_self_uid(my_uid, peer_uid) -> bool {
    peer_uid.contains(&format!("-{install_id}-"))   // main.rs:367–374
}
```

`install_id()` is a per-install random persisted in `device.id` (main.rs:336–350),
embedded in every uid (`mk_uid`, main.rs:363).

- **Dial side (`bring_up_to_known`):** checked at candidate intake —
  `if is_self_uid(&my_uid, v["uid"]) { continue }` (l2.rs:655). Our own install is
  never queued/dialed. ✔
- **Accept side (pair-proof verifier):** checked before secret matching —
  `is_self_uid(...)` short-circuits to `None`/refuse (main.rs:4374–4377). A
  self-originated pair-proof is refused even though our store holds the secret. ✔
- **Direct accept side:** `KnownPeer` self-uid filtered before `start_direct`
  (main.rs:3096). ✔

The fix is present on **both** sides. Two residual notes:

- **Test hook (L-4):** `is_self_uid` returns `false` whenever `FILAMENT_UID` is
  set in the environment (main.rs:368–369), *disabling* the self-connect defense.
  This is a test affordance, but it is an env var, not a compile-time `#[cfg(test)]`
  gate — anyone running the daemon with `FILAMENT_UID` set loses the guard.
- **Substring matching (L-1):** the guard is a `contains("-{id}-")` substring test.
  `install_id` is an 8-hex-char slice of a fresh secret (main.rs:344); collision
  is ~2^-32 and the consequence is a false *positive* (refusing a real peer), not
  a bypass — acceptable, but worth a comment.

---

## 5. Pair-proof binding — bound to DTLS fingerprints? replay/MITM safe?

**Confirmed bound.** `proof_for` mixes **both** certificate fingerprints in sorted
order into the HMAC (main.rs:727–734):

```
HMAC(secret, "filament-proof2:{prover_uid}|{lo_uid}|{hi_uid}|{f_lo}|{f_hi}")
```

A signaling-server (or any) MITM terminates a different DTLS session and therefore
presents different fingerprints, so the MAC it would forward does not validate
against the verifier's own fingerprints (main.rs:722–726). The fingerprints are
read from the **live** local/remote SDP (webrtc.js:350–358 / `p.fingerprints()`),
not from anything the attacker controls. The `prover_uid` direction-tag prevents
reflecting the verifier's own proof back. Replay to a *different* session fails
because the session's fingerprints differ.

The direct-QUIC path achieves the equivalent with RFC-5705 exported keying
material (`keying_material`, direct.rs:327–332) — a relay terminating QUIC on each
leg gets a different exporter value, so the tag can't be forwarded
(direct.rs:324–326, 334–342). Both bindings are correct.

---

## 6. PTY runs as the `up` user (often root) — acceptable? privilege-drop?

`shell_argv()` spawns the up-process user's login shell with no UID change
(main.rs:794–799; the doc comment explicitly defers privilege-drop to a future
`--shell-user`). `serve_pty` inherits the daemon's full environment and spawns the
shell directly (l2.rs:271–285). If `filament up` runs as root (the documented
`--install` systemd service runs as the invoking user, frequently root on a
server), **every granted device gets an interactive root shell** with no audit
beyond an `eprintln!`.

Given the gate (proof + `shell` cap), this is *defensible* for an explicitly
granted device, but it is a sharp edge that pairs badly with **`--shell` granting
all devices** (§2) and the **unbounded fan-out** (§8). This is **Finding M-1**:
ship `--shell-user` (drop to a named non-root account via `setuid`/`CommandBuilder`
before exec, and refuse to spawn a root PTY unless an explicit
`--shell-allow-root` is passed), and document the root risk in the `up --shell`
help text. Until then the risk must be stated loudly in user-facing docs.

---

## 7. SSRF / loopback — can an l2-open or PTY reach a non-loopback target?

**No (for L2 dials).** `accept_control` refuses any `l2-open` whose host is not
loopback: `if !host_is_loopback(&host) { Deny "non-loopback denied" }`
(l2.rs:416–418). `host_is_loopback` accepts only the literal `localhost` or an IP
that parses to a loopback address, and deliberately does **not** resolve arbitrary
DNS names (l2.rs:464–469) — so a name like `internal.corp` is treated as
non-loopback and refused. Port 0 is rejected (l2.rs:409–411). The test-only
`FILAMENT_L2_DIALHOST` override is initiator-side (l2.rs:850) and cannot relax the
acceptor's check. **Solid.**

PTYs don't take a network target at all (the shell is local), so SSRF is N/A there.

One nuance (**L-2**): `host_is_loopback` accepts the **entire** `127.0.0.0/8`
range and `::1`, which is correct for loopback, but a service that bound only to
`127.0.0.1` and relies on other 127.x addresses being unused is unaffected; no
issue. The gate is appropriately *stricter* than `is_private_addr` (no RFC-1918).

---

## 8. Resource / DoS

There is **no concurrency limit anywhere** on the acceptor (confirmed: no
`MAX_STREAMS`/`max_streams`/rate-limit in l2.rs or main.rs). A single trusted,
shell-capable peer can:

- **Flood `pty-open`** with distinct high-half sids — each spawns a login shell
  plus **three OS threads** (reader, writer in `serve_pty` l2.rs:299–321, and the
  portable-pty machinery) and a tokio task (main.rs:4257). Nothing caps the count.
- **Leak `pty_resizers`** — entries are inserted on `pty-open` (main.rs:4254) and
  removed **only** on an explicit `l2-close` for that sid (main.rs:4144–4147). A
  PTY that ends because the **shell exits** (`serve_pty` returns at l2.rs:351–352
  after sending its own `l2-close`) does not pass back through the acceptor's
  `l2-close` arm for the resizer map in all cases, and a peer that simply never
  sends `l2-close` keeps the entry forever. The map grows unbounded across a
  session.
- **Exhaust sids** only theoretically — `alloc_sid` wraps inside the high half
  (l2.rs:91–96), and the acceptor's `accepted` map dedups (l2.rs:386–392) but is
  only cleaned for L2 *dial* streams (l2.rs:446), not PTYs.

This is post-auth (a granted device), so it is **Medium (M-3)**, but a public
"open a terminal from your phone" feature invites exactly this misuse (a buggy or
compromised paired device). Recommended fixes:

- Cap concurrent PTYs per link (e.g. 8) and total streams per link; refuse
  `pty-open` over the cap with an `l2-close{err:"too many sessions"}`.
- Remove the `pty_resizers` entry when `serve_pty` ends — have the spawned task
  signal completion (or sweep entries whose sid is no longer in the mux). Don't
  rely solely on a peer-sent `l2-close`.
- Optionally rate-limit `pty-open`/`l2-open` per link.

---

## Findings (ranked)

### High

**H-1 — Unbounded PTY/stream fan-out + `pty_resizers` map leak (DoS).**
`main.rs:pty-open arm`, `l2.rs:Mux`/`serve_pty`. **STATUS: FIXED.** Added a
per-link cap `MAX_STREAMS_PER_LINK = 8` (enforced in `accept_control` for
`l2-open` and in the `pty-open` arm via `Mux::at_stream_cap`) and a process-wide
`MAX_PTYS_GLOBAL = 32` enforced by an RAII `PtyGuard` (`LIVE_PTYS` atomic). Over
either cap the open is refused with `l2-close{err:"too many streams"}` + a log
line and NO shell is spawned. The `pty_resizers` leak is closed by moving the
resize senders INTO the `Mux` (`resizers` map), so they are dropped on EVERY
teardown path — inbound `l2-close` (`on_close`/`drop_stream`), `serve_pty` exit
(`drop_pty`, including all early-error returns), and link/mux death
(`shutdown_all`). `PtyGuard` frees the global slot on every `serve_pty` exit.
Regression test `l2::h1_tests::pty_open_close_leaves_maps_empty` opens+closes N
PTYs across all three teardown paths and asserts the stream table, resizer map,
and global counter all return to baseline; `per_link_stream_cap_refuses_over_limit`
and `global_pty_cap_is_enforced` cover the caps.

### Medium

**M-1 — Root PTY with no privilege-drop.** `main.rs:shell_argv`, `l2.rs:serve_pty`.
The shell runs as the (often root) up user. **STATUS: FIXED (implemented).**
`up --shell-user <name>` now drops the web-shell/ssh PTY to a named non-root
account via `runuser -l <user>` (threaded through `up_cmd` → `recv_cmd` →
`shell_argv` → `serve_pty`, alongside the existing `--shell` plumbing, and carried
into the systemd unit on `--install`). When a shell policy is active WITHOUT
`--shell-user`, `up` prints a loud banner that PTYs run as the up-process user
(root if the daemon is root) and urges `--shell-user`. **Residual (accepted):**
the no-flag default still runs the PTY as the up user — operators on a root daemon
must pass `--shell-user`. `runuser` requires the daemon itself to be root (it is a
setuid login wrapper with no password prompt), which is exactly the case the flag
de-fangs. TODO(future): refuse a root PTY entirely unless an explicit
`--shell-allow-root` is passed.

**M-2 — `--shell` over-grants to all paired + future devices.** `main.rs:818`,
`main.rs:840`, `main.rs:4409` (pair-intro adds devices later). `ShellPolicy::All`
auto-allows every petname. **STATUS: DOCUMENTED (intentional).** `--shell` is
designed to grant ALL proof-verified paired devices — current and any introduced
later via pair-intro — as a deliberate convenience; `--shell-only <a,b>` is the
scoped alternative. This is now called out in the `ShellPolicy::All` doc comment,
the `up --shell` banner ("ANY paired device, now or paired later"), and here.
**Fix (optional, deferred):** consider excluding `pair-intro`-introduced devices
from `All` unless re-granted.

**M-3 — Multi-line pubkey injection in `shell-bootstrap`.** `main.rs:4182–4195`,
`sshkeys.rs:97–112`. The pubkey is validated only by prefix (`ssh-`/`ecdsa-`,
main.rs:4185); `install_authorized_key` writes `pubkey.trim()` verbatim
(sshkeys.rs:108), which does **not** strip interior newlines. A trusted+shell peer
can send a `pubkey` containing `\n` to inject **additional** authorized_keys lines
(extra keys, `command=`/`from=` options, or a forced-command escape) into the
acceptor's `~/.ssh/authorized_keys`. Bounded by requiring the `shell` cap (the peer
already has shell access), so it is **persistence/escalation-of-an-authorized-peer**,
not unauthenticated RCE. **STATUS: FIXED.** New `sshkeys::validate_pubkey` rejects
any pubkey containing a control character (newline, CR, tab, …) and validates the
shape (`<key-type> <base64-blob> [single-line comment]`, key-type in
`ssh-`/`ecdsa-`/`sk-`, base64 middle). It is enforced in BOTH the `shell-bootstrap`
arm (before install) AND inside `install_authorized_key` (defense in depth — runs
before any filesystem write). Regression test
`sshkeys::tests::validate_pubkey_rejects_multiline_injection` proves a
newline-bearing key is rejected and `install_authorized_key` errors out without
writing.

**M-4 — `shell-bootstrap` reports `$USER` as the login account, decoupled from
where the key was installed.** `main.rs:4198`, `sshkeys.rs:87–89`. The ack returns
`USER` (main.rs:4198) while the key is installed into `authorized_keys_path()`
derived from `HOME` (sshkeys.rs:88). If `up` runs with `HOME` and `USER`
disagreeing (systemd unit, `sudo` without `-i`, container), the initiator pins a
host key and logs in as an account whose `authorized_keys` may not be the one
written — a confusing auth failure at best, and at worst installs the key into an
unexpected account's file. **Fix:** derive both the install target and the reported
login from a single source of truth (the resolved home/owner of the file actually
written).

### Low

**L-1 — `is_self_uid` substring match.** `main.rs:373`. `contains("-{id}-")` can
false-positive on an 8-hex collision (~2^-32); consequence is refusing a real peer,
not a bypass. Document, or match the uid field exactly.

**L-2 — `host_is_loopback` accepts all of 127.0.0.0/8 and ::1.** `l2.rs:464–469`.
Correct for loopback; noted for completeness — no action required.

**L-3 — `caps` hint sent before trust.** `main.rs:4066`, `webrtc.js:387–389`.
Leaks one bit ("offers a terminal") to any connected peer, including pre-verified
WebRTC peers. Not a secret; optionally defer the `caps` send until `trusted` to
avoid advertising the capability to strangers.

**L-4 — `FILAMENT_UID` env var disables the self-connect guard.** `main.rs:368–369`.
A test hook reachable in production via environment. **Fix:** gate it behind a
build cfg or an explicit `FILAMENT_TEST=1`, and never let it neutralize
`is_self_uid` in a release binary.

---

## Ship-readiness verdict

**Ship-blocked on H-1 and M-3; ship-ready once those are fixed and M-1/M-2 are
documented — the trust gate and channel bindings themselves are sound.**

**UPDATE (hardening pass applied):** H-1 and M-3 are FIXED with regression tests;
M-1 is IMPLEMENTED (`--shell-user` privilege-drop + a root-PTY warning banner)
with the no-flag root default left as a documented accepted-risk; M-2 is
DOCUMENTED as intentional (code comment + banner + this doc). `cargo test
--release` green. The Low findings (L-1..L-4) and M-4 are unchanged.
