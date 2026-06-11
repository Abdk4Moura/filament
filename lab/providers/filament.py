"""provider: filament — filament's data channel as the L3 carrier.

THE INTEGRATION TARGET. The point of the whole lab is to develop native L3
(``filament serve_tun``: a TUN whose IP packets ride the data channel directly).
That does NOT exist yet. So this provider is the FIRST APPROXIMATION: it tunnels
the TUN's IP packets over an existing filament **L2 forward/netcat stream**
between two isolated filament identities. It proves filament can carry L3 today
and is the scaffold the native path will replace.

  TODO(serve_tun): replace the TCP-stream hop (forward + two relays) with a
  native ``filament serve_tun`` that reads/writes IP packets on the data channel
  directly — no localhost TCP, no userspace relay framing. When that lands, this
  provider collapses to: create TUN in each netns, run serve_tun on each side.

Datapath today (a -> b)::

    TUN-a (node-a ns)
      -> fil_relay (connect)  --TCP 127.0.0.1:LPORT (host ns)-->
      -> `filament forward LPORT labB RPORT` (config A, host ns)
      ==[ filament DATA CHANNEL / L2 stream ]==>
      -> `filament up` acceptor (config B, host ns, FILAMENT_L2=1)
      -> dials 127.0.0.1:RPORT (host ns)
      -> fil_relay (listen)
      -> TUN-b (node-b ns)

SAFETY: two FULLY ISOLATED filament identities under per-lab FILAMENT_CONFIG_DIRs
— never ~/.config/filament, never the running `up` daemon, never the installed
binary. The locally-built ``cli/target/release/filament`` is used. The filament
processes run in the HOST netns (they need internet for signaling); the TUN fds
are opened via setns from the relays. No host-network mutation.
"""

from __future__ import annotations

import json
import os
import secrets
import sys

from labkit import netns
from labkit.context import LinkContext, FILAMENT_BIN


# Deterministic localhost ports for the L2 forward hop (host-ns localhost).
LPORT = 19098   # filament `forward` listener (node-a side)
RPORT = 19099   # the relay target the acceptor dials (node-b side)


def _seed_identity(config_dir: str, peer_name: str, secret: str,
                   uid_tag: str) -> None:
    os.makedirs(config_dir, exist_ok=True)
    # devices.json: this identity knows the peer under `peer_name`, shared secret,
    # with the caps the L2 acceptor needs (transfer baseline + shell, which also
    # covers the trusted-device gate the L2 forward acceptor checks).
    devices = [{
        "name": peer_name, "secret": secret, "v": 2,
        "caps": ["transfer", "shell"],
    }]
    with open(os.path.join(config_dir, "devices.json"), "w") as f:
        json.dump(devices, f)
    # Pin a distinct device.id so the two identities never see each other as
    # "self" (is_self_uid keys on device.id).
    with open(os.path.join(config_dir, "device.id"), "w") as f:
        f.write(uid_tag)


def up(ctx: LinkContext) -> None:
    if not FILAMENT_BIN.exists():
        raise RuntimeError(
            f"locally-built filament not found at {FILAMENT_BIN}; "
            f"build it: (cd cli && cargo build --release).")

    # --- per-lab isolated config dirs ---
    cfg_a = os.path.join(ctx.log_dir, "fil-A")
    cfg_b = os.path.join(ctx.log_dir, "fil-B")
    secret = ctx.ledger.meta("fil_secret") or secrets.token_hex(32)
    ctx.ledger.set_meta("fil_secret", secret)

    # A knows B as "labB-<lab>"; B knows A as "labA-<lab>" (names unique per lab
    # so concurrent labs never cross-talk on the shared signaling channel).
    name_b = f"labB-{ctx.topo.name}"
    name_a = f"labA-{ctx.topo.name}"
    _seed_identity(cfg_a, name_b, secret, f"labA{ctx.topo.name}")
    _seed_identity(cfg_b, name_a, secret, f"labB{ctx.topo.name}")
    ctx.ledger.add("file", cfg_a)
    ctx.ledger.add("file", cfg_b)
    ctx.ledger.set_meta("fil_names", {"a": name_a, "b": name_b})

    server = os.environ.get("FILAMENT_SERVER",
                            "https://api.filament.autumated.com")
    fb = str(FILAMENT_BIN)

    # The TUN is the data path for filament: address the overlay on it. The relay
    # bridges TUN <-> filament L2 stream.
    for ep in ctx.endpoints:
        netns.addr_add(ep.ns, ctx.tun_iface(ep),
                       f"{ep.overlay_ip}/{ctx.overlay_prefixlen}")

    # --- node-b relay: listen on RPORT, bridge to TUN-b ---
    relay_b = netns.spawn(
        [sys.executable, os.path.join(os.path.dirname(__file__), "fil_relay.py"),
         "--ns", ctx.b.ns, "--tun", ctx.tun_iface(ctx.b),
         "--role", "listen", "--port", str(RPORT)],
        ns=None, logfile=ctx.log("relay-b"))
    ctx.ledger.add("pid", str(relay_b), role="relay-b")

    # --- node-b filament acceptor (up, FILAMENT_L2=1, isolated config) ---
    up_pid = netns.spawn(
        [fb, "--server", server, "up", "--name-as", f"{name_b}-acceptor"],
        ns=None, logfile=ctx.log("fil-up-b"),
        env={"FILAMENT_CONFIG_DIR": cfg_b, "FILAMENT_L2": "1",
             "FILAMENT_UID": f"labBuid{ctx.topo.name}"})
    ctx.ledger.add("pid", str(up_pid), role="fil-up-b")

    # Let the acceptor reach the signaling server and subscribe BEFORE the
    # initiator starts dialing. Without this head-start the forward can dial
    # before the acceptor is present/subscribed, producing connect churn (the
    # initiator rotates candidates) that delays — or, on a same-host loopback
    # direct-quic race, destabilizes — the first link.
    _await_acceptor_ready(ctx.log("fil-up-b"), timeout=15.0)

    # --- node-a filament forward: LPORT -> labB:127.0.0.1:RPORT ---
    fwd_pid = netns.spawn(
        [fb, "--server", server, "forward", str(LPORT), name_b, str(RPORT)],
        ns=None, logfile=ctx.log("fil-fwd-a"),
        env={"FILAMENT_CONFIG_DIR": cfg_a,
             "FILAMENT_UID": f"labAuid{ctx.topo.name}"})
    ctx.ledger.add("pid", str(fwd_pid), role="fil-fwd-a")

    # --- node-a relay: connect to LPORT, bridge to TUN-a ---
    relay_a = netns.spawn(
        [sys.executable, os.path.join(os.path.dirname(__file__), "fil_relay.py"),
         "--ns", ctx.a.ns, "--tun", ctx.tun_iface(ctx.a),
         "--role", "connect", "--port", str(LPORT)],
        ns=None, logfile=ctx.log("relay-a"))
    ctx.ledger.add("pid", str(relay_a), role="relay-a")

    # Route: each node reaches the peer's overlay IP via its own TUN (the relay
    # carries it). Add an explicit /32 route to the peer over the TUN.
    for ep in ctx.endpoints:
        peer = ctx.other(ep)
        netns.route_add(ep.ns, f"{peer.overlay_ip}/32",
                        dev=ctx.tun_iface(ep))

    ctx.ledger.set_meta("fil_ports", {"lport": LPORT, "rport": RPORT})
    ctx.ledger.set_meta(
        "fil_note",
        "L2-forward APPROXIMATION (TODO: native serve_tun). The filament data "
        "channel + relay chain can take several seconds to wire; `up` waits for "
        "the path, and `lab probe ping` also retries.")

    # Wait for the data path to actually carry a packet before returning, so the
    # caller (and the very next `lab probe`) sees a ready tunnel. The filament
    # data channel + 4-hop relay chain typically wires in 2-6s; we allow 30s.
    _wait_data_path(ctx, timeout=30.0)


def _await_acceptor_ready(logpath: str, timeout: float) -> None:
    """Wait until the acceptor's `up` log shows it is live (ready banner), so the
    initiator only starts dialing once the peer is present + subscribed."""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(logpath) as f:
                txt = f.read()
            if "filament up" in txt or "known device" in txt:
                time.sleep(1.0)  # small settle for the subscribe round-trip
                return
        except OSError:
            pass
        time.sleep(0.5)


def _wait_data_path(ctx: LinkContext, timeout: float) -> None:
    """Poll a ping across the overlay until it succeeds (or timeout). Best-effort
    — a failure here is not fatal (the probe will report it), but waiting makes
    bring-up deterministic for scripted/AI use."""
    import time
    deadline = time.time() + timeout
    target = ctx.b.overlay_ip
    while time.time() < deadline:
        ok, _ = netns.ping(ctx.a.ns, target, count=1, timeout_s=1)
        if ok:
            ctx.ledger.set_meta("fil_ready", True)
            return
        time.sleep(1.0)
    ctx.ledger.set_meta("fil_ready", False)


def down(ctx: LinkContext) -> None:
    # All filament processes + relays are tracked as `pid` resources and the
    # config dirs as `file` resources; the ledger sweep handles them.
    pass
