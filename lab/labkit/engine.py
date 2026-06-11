"""engine.py — realize (up) and destroy (down) a declarative topology.

The netlab-inspired lifecycle core. ``up`` is idempotent (re-running is safe) and
``down`` is a robust ledger sweep that cleans up EVERY resource the lab created,
even after a partial/failed ``up`` — no leaked namespaces, ifaces, or processes.

up(topo, link, crypto):
    1. preflight (doctor) for the chosen link; abort with hints on fatal misses.
    2. create a netns per node (idempotent), record each in the ledger.
    3. create + address a TUN in each node on the overlay subnet (primitive tun).
    4. validate crypto vs provider; run the provider's up() to establish carriage.
    5. persist node info for probe/status.

down(lab):
    walk the ledger in REVERSE insertion order, destroying each resource by kind.
    netns deletion is the backstop (it frees any iface still inside). Idempotent.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
import sys
from typing import Optional

from labkit import netns, doctor
from labkit.state import Ledger, load as load_ledger
from labkit.context import LinkContext
from labkit.topology import Topology, load as load_topology
from primitives import tun as tun_prim, crypto as crypto_prim
import providers


LOG_ROOT = Path(__file__).resolve().parent.parent / ".state" / "logs"


def log_dir_for(lab: str) -> str:
    d = LOG_ROOT / lab
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


class LabError(RuntimeError):
    pass


def up(topo_name: str, link: Optional[str] = None,
       crypto: Optional[str] = None, run_doctor: bool = True) -> Ledger:
    topo: Topology = load_topology(topo_name)
    provider_name = link or topo.link.provider
    crypto_name = crypto or topo.link.params.get("crypto") or _default_crypto(provider_name)

    # 1) preflight
    if run_doctor:
        rep = doctor.run(link=provider_name)
        if not rep.ok():
            raise LabError(
                "preflight failed for link=%s:\n%s" % (
                    provider_name, doctor.format_report(rep)))

    # crypto coherence (cheap, do it before touching the host)
    crypto_prim.validate(crypto_name, provider_name)

    ledger = Ledger(topo.name)
    ledger.data["topology"] = topo.name
    ledger.data["link"] = provider_name
    ledger.set_meta("crypto", crypto_name)
    ledger.save()

    ld = log_dir_for(topo.name)
    ctx = LinkContext(topo, ledger, provider_name, crypto_name, ld)

    try:
        # 2) namespaces
        for ep in ctx.endpoints:
            netns.ns_add(ep.ns)
            ledger.add("netns", ep.ns)
            ledger.set_node(ep.node, netns=ep.ns,
                            overlay_ip=ep.overlay_ip,
                            underlay_ip=ep.underlay_ip,
                            tun=ctx.tun_iface(ep))

        # 3) TUN per node — created BARE (no overlay address). Each provider
        #    addresses the overlay on its OWN data-path iface (tun for udp/
        #    filament; veth for pipe; wg iface for wg), so a carrier-less TUN
        #    never wins a competing on-link route to the real path.
        for ep in ctx.endpoints:
            tun_prim.create(ledger, ep.ns, ctx.tun_iface(ep), mtu=ctx.mtu)

        # 4) the carrier
        provider = providers.get(provider_name)
        provider.up(ctx)

        # record each node's DATA-PATH iface (where a fault must be applied to
        # actually degrade traffic): tun for udp/filament, veth for pipe, wg
        # iface for wg. fault() targets this, not the (maybe-unused) tun.
        for ep in ctx.endpoints:
            ledger.set_node(ep.node, datapath_iface=_datapath_iface(ctx, ep))

        ledger.set_meta("state", "up")
        ledger.save()
    except Exception:
        # Best-effort: leave the ledger in place so `down` can sweep what we
        # half-created. Re-raise so the CLI surfaces the failure.
        ledger.set_meta("state", "partial")
        ledger.save()
        raise

    return ledger


def _datapath_iface(ctx: LinkContext, ep) -> str:
    """The iface carrying real traffic for this carrier (fault target)."""
    p = ctx.provider
    if p in ("pipe", "veth"):
        return ctx.underlay_iface(ep)     # the veth
    if p == "wg":
        return ctx.wg_iface(ep)           # the wg iface
    return ctx.tun_iface(ep)              # udp / filament use the tun


def _default_crypto(provider: str) -> str:
    return {"pipe": "none", "udp": "none", "wg": "wg-noise",
            "filament": "none"}.get(provider, "none")


def down(lab: str, purge_logs: bool = False) -> bool:
    """Destroy everything the lab created. Idempotent. Returns True if a ledger
    existed (False = nothing to do)."""
    ledger = load_ledger(lab)
    if ledger is None:
        return False

    for r in ledger.resources_reversed():
        try:
            _destroy(r)
        except Exception as e:  # never let one stuck resource block the rest
            print(f"lab down: warning: failed to destroy {r}: {e}",
                  file=sys.stderr)

    # logs/scratch
    if purge_logs:
        shutil.rmtree(LOG_ROOT / lab, ignore_errors=True)

    ledger.remove()
    return True


def _destroy(r: dict) -> None:
    kind, name = r["kind"], r["name"]
    if kind == "pid":
        netns.kill(int(name))
    elif kind == "tc":
        netns.tc_clear(r.get("ns", ""), name)
    elif kind == "wg":
        ns = r.get("ns")
        if ns and netns.ns_exists(ns):
            netns.nsx(ns, "ip", "link", "del", name, check=False)
    elif kind == "tun":
        ns = r.get("ns")
        if ns and netns.ns_exists(ns):
            netns.nsx(ns, "ip", "link", "del", name, check=False)
    elif kind == "veth":
        # deleting either end deletes the pair; try the recorded end's ns.
        ns = r.get("ns")
        if ns and netns.ns_exists(ns):
            netns.nsx(ns, "ip", "link", "del", name, check=False)
    elif kind == "netns":
        netns.ns_del(name)
    elif kind == "file":
        p = Path(name)
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                p.unlink()
            except FileNotFoundError:
                pass


def down_all(purge_logs: bool = False) -> dict:
    """Tear down every lab with a ledger, then sweep any stray lab-prefixed
    namespaces (belt-and-suspenders, even with no ledger). Returns a summary."""
    from labkit.state import list_labs
    summary = {"labs": [], "stray_namespaces": []}
    for lab in list_labs():
        if down(lab, purge_logs=purge_logs):
            summary["labs"].append(lab)
    # stray sweep: any lab-<...> namespace not removed above
    for ns in netns.list_lab_namespaces():
        netns.ns_del(ns)
        summary["stray_namespaces"].append(ns)
    # stray host-ns ifaces (only from a crashed veth_add before relocation)
    summary["stray_host_ifaces"] = []
    for iface in netns.list_stray_host_ifaces():
        netns.del_host_iface(iface)
        summary["stray_host_ifaces"].append(iface)
    return summary
