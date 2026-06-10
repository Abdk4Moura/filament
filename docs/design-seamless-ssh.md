# Design: seamless `filament ssh <peer>` — zero-setup shell over the trusted channel

Status: implementing (additive; gated). Owner: transport.
Companion to: `docs/L1-pake-protocol.md` (caps model), `docs/L2-tunnel-design.md`
(the netcat/forward/ssh tunnel), `docs/design-direct-cli-transport.md` (rung-1
direct QUIC).

## Goal

Make `filament ssh <peer>` as seamless as `tailscale ssh`: from a client with
**no ssh keypair and no ssh setup at all**, `filament ssh peer 'hostname'` lands
a shell and returns the peer's hostname — **no key copying, no host-key prompt,
no `~/.ssh` involvement**.

Today `filament ssh` is `ssh -o ProxyCommand="filament netcat <peer> 22"`. The
data path works, but it inherits OpenSSH's two friction points:

1. **user-key auth** ("who are you") — needs a keypair in `~/.ssh` and its pubkey
   in the peer's `authorized_keys`.
2. **host-key check** ("is this the right host") — needs a known_hosts entry or a
   TOFU prompt.

## Why both checks are redundant here (and safe to bootstrap)

Pairing already mutually authenticates the channel: SPAKE2 + a key-confirmation
MAC folded over the **sorted DTLS/QUIC fingerprints + caps** (see
`pake/src/lib.rs::confirm_mac`, `docs/L1-pake-protocol.md` §4/§6.1). A MITM cannot
sit inside a paired link: substituting a transport cert or rewriting caps breaks
the MAC. On every later link the same identity is re-proved (`pair-proof`, bound
to the live fingerprints) before `trusted` is set.

So, **over a `trusted` link to a device that holds the `shell` capability**:

- host-key check → the channel is already MITM-proof, so fetching the peer's real
  host key over it and pinning it is sound (TOFU over an authenticated channel).
- user-key auth → already answered ("a trusted, shell-granted paired device"); we
  may install our managed pubkey into the peer's `authorized_keys`.

Neither bypass weakens anything: we are not skipping authentication, we are
**bootstrapping ssh's auth material over a channel that is already at least as
strongly authenticated as ssh would be.**

## Hard security boundary: `shell` is a NEW capability, deny-by-default

Pairing for file transfer grants `caps: ["transfer"]` ONLY (`pair_v2_caps`).
**Shell access MUST NOT be auto-granted from `transfer`.** A device that can send
you a file must NOT, by that fact, get a shell.

- New capability string: `"shell"`.
- Granted only by an explicit, local, consenting action on the ACCEPTOR:
  `filament grant <device> shell`. (No interactive prompt inside `up`: a
  backgrounded daemon cannot prompt; the explicit grant command is the
  deny-by-default consent gate and keeps the path headless/testable.)
- `filament revoke <device> shell` removes the cap AND strips the managed
  `authorized_keys` block.
- Enforcement is at the **bootstrap**, not at ssh-auth-failure time: a device
  without `shell` that requests the bootstrap is refused with a clear `deny`, and
  `filament ssh` aborts BEFORE invoking ssh. ("Zero shell, clear denial" — not a
  muddy auth failure.)

The cap is keyed by the **devices.json petname**. The acceptor verifies a link's
identity in the `pair-proof` arm, where the matching record `(petname, secret)`
is known; we record that petname on the link (`verified_name`) so the bootstrap
gate looks the cap up under the exact stored key.

## The bootstrap exchange (pure control JSON over the trusted transport)

Two **separate** known-device bring-ups (no threading one link through both the
bootstrap and the ssh subprocess — simpler and equally correct):

1. `filament ssh <peer>` first runs the bootstrap over its own link, then exits
   that link and spawns ssh whose ProxyCommand is a fresh `filament netcat` link.

Bootstrap, initiator side (`shell_bootstrap`):
- `bring_up_to_known(server, peer, relay)` → authenticated transport.
- Ensure our managed keypair exists (generate on demand, see below); read its
  pubkey.
- Send control `{type:"shell-bootstrap", v:1, pubkey:"ssh-ed25519 AAAA... filament-managed"}`.
- Pump `rx` for:
  - `{type:"shell-bootstrap-ack", hostkeys:[...], user:"<login>"}` → install the
    host keys into our private known_hosts pinned to the destination token, then
    proceed to spawn ssh.
  - `{type:"shell-bootstrap-deny", reason:"..."}` → abort with a clear message,
    do NOT spawn ssh.
  - timeout → abort.

Bootstrap, acceptor side (new `Ev::Control` arm in `up`, next to `l2-open`,
**gated on `FILAMENT_L2=1` like the rest of the tunnel acceptor**):
- Resolve the link's verified petname; require `l.trusted &&
  device_allows(name, "shell")`. (Localhost/SSRF rules are irrelevant here — no
  dial happens; this is a local file edit + host-key read.)
- Granted:
  - Append/replace our managed block in `$HOME/.ssh/authorized_keys`:
    ```
    # BEGIN filament-managed <device>
    <pubkey>
    # END filament-managed <device>
    ```
    Idempotent: a re-grant replaces the block for that device (no dup lines).
    File created `0700` dir / `0600` file if absent. Marked, auditable, removable.
  - Read the host's public host keys (prod: `/etc/ssh/ssh_host_*.pub`;
    env-overridable `FILAMENT_SSH_HOSTKEY` for the gate's throwaway sshd).
  - Reply `shell-bootstrap-ack{hostkeys, user}`.
- Not granted: reply `shell-bootstrap-deny{reason:"shell capability not granted"}`
  and log `l2: shell bootstrap refused: <device> (no shell cap)`.

## filament-managed ssh material (never touches `~/.ssh`)

Under the filament config dir (`FILAMENT_CONFIG_DIR`, default `~/.config/filament`):

- `ssh/id_ed25519` + `ssh/id_ed25519.pub` — managed keypair, generated on demand
  via `ssh-keygen -t ed25519 -N "" -C filament-managed`, `0600`. NEVER the user's
  `~/.ssh`.
- `ssh/known_hosts` — filament-private pin store.

`filament ssh peer [args]` then invokes:

```
ssh -o IdentityFile=<cfg>/ssh/id_ed25519 \
    -o IdentitiesOnly=yes \
    -o UserKnownHostsFile=<cfg>/ssh/known_hosts \
    -o GlobalKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=accept-new \
    -o ProxyCommand="filament --server <s> [--relay] netcat <peer> 22" \
    <login>@<dest-token> [args]
```

- `IdentitiesOnly=yes` + our `IdentityFile` ⇒ no `~/.ssh` keys, no agent.
- our `UserKnownHostsFile` + pinned entry ⇒ no prompt. `accept-new` is the
  backstop (and is itself safe — TOFU over the MITM-proof tunnel). A *wrong*
  pre-pin would be worse than none (hard mismatch), so the acceptor pins its
  **real** served host key; `accept-new` only fires if the pin is somehow absent.
- known_hosts entry is keyed by the **exact destination token** ssh uses (we
  control it in the seamless path); `HashKnownHosts` left default but we write the
  plain token so the pin is not silently inert.

## Best transport, no flags (item 3)

The L2/ssh path (the bootstrap link AND the ProxyCommand `netcat` child) should
prefer the **direct-QUIC** transport to a known device, falling back to WebRTC,
**without the user setting `FILAMENT_DIRECT`**. Scope this to `bring_up_to_known`
ONLY (the tunnel path) — do NOT flip the global file-transfer default, so file
transfer / pairing / existing FILAMENT_DIRECT behavior cannot regress.

Mechanism: `bring_up_to_known` treats a known-device link as "try direct first"
by default. `FILAMENT_DIRECT=0` can still force WebRTC-only for that path; absence
of the var no longer means "WebRTC only" *for this path*. Direct is attempted with
a short budget and falls back to the existing WebRTC bring-up on failure. (If the
direct dial wiring proves too invasive for this rung, the fallback path is the
existing WebRTC bring-up, so the feature still works end-to-end; the direct
preference is a transport optimization, not a correctness requirement.)

## Surfaces / CLI additions

- `filament grant <device> shell` — acceptor-side consent; adds `"shell"` to the
  device's caps (deny-by-default; only a known device).
- `filament revoke <device> shell` — removes the cap + strips the managed block.
- `filament ssh <peer> [args]` — now runs the bootstrap first (gated: only when
  the peer is expected to accept; if bootstrap is denied, abort cleanly).
- `CMDS` array + dispatch extended (must stay in lockstep or the bare-code
  heuristic / clap break).

## Validation gates (no self-cert)

New `cli/tests/ssh-gates.sh`, hermetic, fixture backend, sandboxed `HOME`:

- **GATE A (positive, no-keys bootstrap):** client config dir has NO ssh keypair
  and NO `~/.ssh`. `grant boxA shell` on the acceptor, then
  `filament ssh boxB 'hostname'` returns the acceptor's hostname. Proves the full
  zero-setup bootstrap (key gen + authorized_keys install + host-key pin + ssh).
- **GATE B (negative, no cap):** a paired device WITHOUT `shell` is REFUSED the
  bootstrap (`shell-bootstrap-deny`), `filament ssh` aborts before invoking ssh,
  zero shell. Clear denial in output.
- **Marked + removable:** assert the `# BEGIN/END filament-managed <device>` block
  is present after grant and gone after `revoke`.
- **No regression:** `gates.sh` (pairing + transfer core), `transport-gates.sh`
  (rung-1 direct), `l2-gates.sh` still pass.

## Non-goals / for review

- Port-22 `l2-open` cap-gating (refusing a raw `netcat <peer> 22` from a device
  without `shell`) is defense-in-depth, noted but NOT the load-bearing boundary —
  the bootstrap key-install gate is. Adding it must not regress `forward` to other
  loopback ports. Left as a follow-up unless cheap.
- Multi-user / per-login authorized_keys selection: we install into the acceptor
  daemon user's `authorized_keys` and report that login back; ssh connects as it.
