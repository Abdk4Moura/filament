"""provider: wg — a real WireGuard tunnel between the two namespaces.

Proves the provider abstraction against production-grade encrypted carriage. The
overlay (TUN) subnet rides inside a WireGuard tunnel whose underlay is the veth
pair (so wg's UDP endpoints reach each other over the lab's private wire, never
the host).

Datapath:
  * kernel WireGuard if the module is available (the fast path; `ip link add type
    wireguard`), else
  * a userspace fallback (wireguard-go / boringtun) creating the wg iface — same
    `wg` config tooling, just a userspace device. (Detected by doctor; if neither
    is present `up` refuses with an install hint.)

Each node gets a wg iface addressed on the OVERLAY subnet; the peer is configured
with the other's pubkey, the veth underlay endpoint, and allowed-ips = the peer's
overlay /32 (cryptokey routing — the route primitive's model, enforced by wg
itself). A fixed listen-port per side keeps it deterministic.

Keys live in the per-lab log/scratch dir (recorded as `file` resources so
teardown unlinks them); they never touch ~/.config or any real wg config.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from labkit import netns
from labkit.context import LinkContext, Endpoint
from providers import underlay


WG_PORT_A = 51820
WG_PORT_B = 51821


def _genkey() -> tuple:
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True,
                          check=True).stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True,
                         text=True, check=True).stdout.strip()
    return priv, pub


def _kernel_wg_available() -> bool:
    try:
        subprocess.run(["modprobe", "wireguard"], capture_output=True, timeout=10)
    except Exception:
        pass
    # Probe by attempting to create + delete a throwaway wg iface in host ns.
    r = subprocess.run(["ip", "link", "add", "labwgcheck", "type", "wireguard"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        subprocess.run(["ip", "link", "del", "labwgcheck"], capture_output=True)
        return True
    return False


def _make_wg_iface(ns: str, iface: str, userspace_tool: str = None) -> None:
    """Create the wg iface inside the netns (kernel or userspace device)."""
    if userspace_tool is None:
        netns.nsx(ns, "ip", "link", "add", iface, "type", "wireguard")
    else:
        # wireguard-go / boringtun create the device when run in the netns.
        # They daemonize by default; we run them foreground-detached and they
        # leave the iface behind. The process is tracked so teardown kills it.
        raise RuntimeError("_make_wg_iface userspace path handled in up()")


def up(ctx: LinkContext) -> None:
    underlay.establish(ctx)

    kernel = _kernel_wg_available()
    userspace = None
    if not kernel:
        for cand in ("wireguard-go", "boringtun"):
            if shutil.which(cand):
                userspace = cand
                break
        if userspace is None:
            raise RuntimeError(
                "no WireGuard datapath: kernel module unavailable and no "
                "wireguard-go/boringtun found. Install one (see `lab doctor`).")
    ctx.ledger.set_meta("wg_datapath", "kernel" if kernel else userspace)

    a_priv, a_pub = _genkey()
    b_priv, b_pub = _genkey()

    # Persist keys as scratch files (recorded for teardown).
    keydir = ctx.log_dir
    for nm, val in (("a.priv", a_priv), ("b.priv", b_priv)):
        p = os.path.join(keydir, f"wg-{nm}")
        with open(p, "w") as f:
            f.write(val)
        os.chmod(p, 0o600)
        ctx.ledger.add("file", p)

    plan = [
        (ctx.a, ctx.wg_iface(ctx.a), a_priv, WG_PORT_A, b_pub,
         ctx.b.underlay_ip, WG_PORT_B),
        (ctx.b, ctx.wg_iface(ctx.b), b_priv, WG_PORT_B, a_pub,
         ctx.a.underlay_ip, WG_PORT_A),
    ]

    for ep, iface, priv, port, peer_pub, peer_endpoint, peer_port in plan:
        peer = ctx.other(ep)
        if userspace:
            logf = ctx.log(f"wireguard-go-{ep.node}")
            env = {"WG_TUN_NAME_FILE": "/dev/null"}
            pid = netns.spawn([userspace, "-f", iface], ns=ep.ns,
                              logfile=logf, env=env)
            ctx.ledger.add("pid", str(pid), role=f"wireguard-go-{ep.node}",
                           ns=ep.ns)
            # give the userspace device a moment to appear
            _wait_iface(ep.ns, iface, tries=50)
        else:
            netns.nsx(ep.ns, "ip", "link", "add", iface, "type", "wireguard")
        ctx.ledger.add("wg", iface, ns=ep.ns)

        # configure key + listen port via a private temp key file
        keyfile = os.path.join(keydir, f"wgkey-{ep.node}")
        with open(keyfile, "w") as f:
            f.write(priv)
        os.chmod(keyfile, 0o600)
        ctx.ledger.add("file", keyfile)
        netns.nsx(ep.ns, "wg", "set", iface, "listen-port", str(port),
                  "private-key", keyfile)

        # peer config: pubkey, underlay endpoint, allowed-ips = peer overlay /32
        netns.nsx(ep.ns, "wg", "set", iface, "peer", peer_pub,
                  "endpoint", f"{peer_endpoint}:{peer_port}",
                  "allowed-ips", f"{peer.overlay_ip}/32",
                  "persistent-keepalive", "5")

        # address the wg iface on the overlay subnet + bring up
        netns.addr_add(ep.ns, iface,
                       f"{ep.overlay_ip}/{ctx.overlay_prefixlen}")
        netns.nsx(ep.ns, "ip", "link", "set", iface, "mtu", str(ctx.mtu))
        netns.link_up(ep.ns, iface)


def _wait_iface(ns: str, iface: str, tries: int = 50) -> None:
    import time
    for _ in range(tries):
        if netns.iface_in_ns(iface, ns):
            return
        time.sleep(0.1)


def down(ctx: LinkContext) -> None:
    # ledger sweep handles wg ifaces, pids, key files, veth, netns.
    pass
