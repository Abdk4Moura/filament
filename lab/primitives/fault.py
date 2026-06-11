"""primitive 6 — fault: induce adverse conditions for testing.

Two families:

  netem faults (loss / latency / bandwidth) — attach a `tc netem` qdisc to the
  carrier-side iface inside a node's netns. Degrades but does not break the path.

  STALL — freeze the data path while the link stays nominally "up". This is the
  one that matters for the P0 transport-resilience work: a stalled tunnel still
  shows "connected" but moves zero bytes, which is exactly the failure mode the
  resilience self-heal must detect and recover from. We implement stall as a
  100% netem loss in BOTH directions on the carrier iface — packets enter and
  vanish, the iface/link never goes down, no FIN/RST is sent. ``unstall`` lifts
  it, so the lab can later demonstrate the self-heal resuming flow.

All faults are applied to a carrier underlay iface inside a netns; the host is
never touched. Faults are recorded in the ledger so teardown clears the qdisc
(and netns deletion is the backstop).

Interface:
    apply(ledger, ns, iface, kind, **params) -> None
        kind in {loss, latency, bandwidth, stall}
    clear(ledger, ns, iface) -> None
"""

from __future__ import annotations

from labkit import netns


def apply(ledger, ns: str, iface: str, kind: str, **params) -> str:
    """Apply a fault to ``iface`` inside ``ns``. Returns a human description."""
    if kind == "loss":
        pct = params.get("percent", params.get("loss", "10%"))
        if not str(pct).endswith("%"):
            pct = f"{pct}%"
        netns.tc_netem_add(ns, iface, loss=pct)
        desc = f"loss {pct}"
    elif kind == "latency":
        delay = params.get("delay", params.get("ms", "50ms"))
        if not str(delay).endswith("ms"):
            delay = f"{delay}ms"
        jitter = params.get("jitter")
        if jitter:
            if not str(jitter).endswith("ms"):
                jitter = f"{jitter}ms"
            netns.tc_netem_add(ns, iface, delay=f"{delay} {jitter}")
            desc = f"latency {delay} +/- {jitter}"
        else:
            netns.tc_netem_add(ns, iface, delay=delay)
            desc = f"latency {delay}"
    elif kind == "bandwidth":
        rate = params.get("rate", "1mbit")
        netns.tc_netem_add(ns, iface, rate=rate)
        desc = f"bandwidth {rate}"
    elif kind == "stall":
        # 100% loss: the iface stays UP, the carrier sees no close, but every
        # packet is dropped — a frozen-but-"connected" tunnel. The resilience
        # work must detect THIS, not a clean link-down.
        netns.tc_netem_add(ns, iface, loss="100%")
        desc = "STALL (100% loss; link stays up, zero bytes flow)"
    else:
        raise ValueError(
            f"unknown fault {kind!r}; choose loss|latency|bandwidth|stall")

    ledger.add("tc", iface, ns=ns)
    ledger.set_meta("fault", {"ns": ns, "iface": iface, "kind": kind,
                              "desc": desc})
    return desc


def clear(ledger, ns: str, iface: str) -> None:
    netns.tc_clear(ns, iface)
    ledger.forget("tc", iface)
    ledger.set_meta("fault", None)
