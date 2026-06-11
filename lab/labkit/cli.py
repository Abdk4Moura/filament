"""cli.py — the argparse front-end behind the `lab` command.

Subcommands:
  up <topology> [--link pipe|udp|wg|filament] [--crypto ...] [--no-doctor]
  down [<lab>] [--all] [--purge-logs]
  status [<lab>]
  probe <ping|iperf|curl|counters> [<lab>]
  compose <tun|link|fault|...>          (wire/inspect individual primitives)
  fault <loss|latency|bandwidth|stall|clear> [<lab>] [params]
  doctor [--link ...]
  list

Designed to be both human- and AI-drivable: ``--json`` makes every command emit
machine-readable output (the lab Claude skill relies on this).
"""

from __future__ import annotations

import argparse
import json
import sys

from labkit import engine, doctor, netns
from labkit.state import Ledger, load as load_ledger, list_labs
from labkit.topology import load as load_topology
from labkit.context import LinkContext
from primitives import fault as fault_prim
from probe import probe as probe_mod


def _emit(obj, as_json: bool, human=None):
    if as_json:
        print(json.dumps(obj, indent=2))
    elif human is not None:
        print(human)
    else:
        print(obj)


def _only_lab(lab_arg):
    """Resolve the target lab: the named one, or the sole running one."""
    if lab_arg:
        return lab_arg
    labs = list_labs()
    if len(labs) == 1:
        return labs[0]
    if not labs:
        raise SystemExit("no labs are up. Run `lab up <topology>` first.")
    raise SystemExit(f"multiple labs up ({', '.join(labs)}); name one.")


def cmd_up(args) -> int:
    try:
        ledger = engine.up(args.topology, link=args.link, crypto=args.crypto,
                           run_doctor=not args.no_doctor)
    except engine.LabError as e:
        print(str(e), file=sys.stderr)
        return 2
    info = {
        "lab": ledger.lab, "topology": ledger.data["topology"],
        "link": ledger.data["link"], "crypto": ledger.meta("crypto"),
        "nodes": ledger.nodes(),
        "note": ledger.meta("fil_note"),
    }
    human = (f"lab '{ledger.lab}' up  (link={ledger.data['link']}, "
             f"crypto={ledger.meta('crypto')})\n"
             + "\n".join(
                 f"  {n}: ns={d['netns']} overlay={d['overlay_ip']} tun={d['tun']}"
                 for n, d in ledger.nodes().items()))
    if info["note"]:
        human += f"\n  note: {info['note']}"
    human += f"\n  next: lab probe ping {ledger.lab}"
    _emit(info, args.json, human)
    return 0


def cmd_down(args) -> int:
    if args.all:
        summary = engine.down_all(purge_logs=args.purge_logs)
        _emit(summary, args.json,
              f"tore down labs: {summary['labs'] or '(none)'}; "
              f"swept stray ns: {summary['stray_namespaces'] or '(none)'}; "
              f"swept stray ifaces: "
              f"{summary.get('stray_host_ifaces') or '(none)'}")
        return 0
    lab = _only_lab(args.lab)
    existed = engine.down(lab, purge_logs=args.purge_logs)
    _emit({"lab": lab, "torn_down": existed}, args.json,
          f"lab '{lab}' torn down" if existed else f"no such lab '{lab}'")
    return 0


def cmd_status(args) -> int:
    if args.lab:
        labs = [args.lab]
    else:
        labs = list_labs()
    report = []
    for lab in labs:
        led = load_ledger(lab)
        if led is None:
            continue
        live = []
        for r in led.resources():
            if r["kind"] == "pid":
                live.append({"role": r.get("role", "?"), "pid": int(r["name"]),
                             "alive": netns.pid_alive(int(r["name"]))})
        report.append({
            "lab": lab, "topology": led.data["topology"],
            "link": led.data["link"], "crypto": led.meta("crypto"),
            "state": led.meta("state"), "nodes": led.nodes(),
            "processes": live,
            "fault": led.meta("fault"),
            "resource_count": len(led.resources()),
        })
    if args.json:
        _emit(report, True)
    else:
        if not report:
            print("no labs are up.")
        for r in report:
            print(f"lab '{r['lab']}': {r['topology']} link={r['link']} "
                  f"crypto={r['crypto']} state={r['state']} "
                  f"({r['resource_count']} resources)")
            for n, d in r["nodes"].items():
                print(f"  node {n}: ns={d['netns']} overlay={d['overlay_ip']}")
            for p in r["processes"]:
                print(f"  proc {p['role']}: pid={p['pid']} "
                      f"{'ALIVE' if p['alive'] else 'DEAD'}")
            if r["fault"]:
                print(f"  fault: {r['fault']['desc']} on "
                      f"{r['fault']['ns']}/{r['fault']['iface']}")
    return 0


def cmd_probe(args) -> int:
    lab = _only_lab(args.lab)
    led = load_ledger(lab)
    if led is None:
        raise SystemExit(f"no such lab '{lab}'")
    kind = args.kind
    if kind == "ping":
        result = probe_mod.ping(led, count=args.count)
    elif kind == "iperf":
        result = probe_mod.iperf(led, seconds=args.seconds)
    elif kind == "curl":
        result = probe_mod.curl(led)
    elif kind == "counters":
        result = probe_mod.counters(led)
    else:
        raise SystemExit(f"unknown probe '{kind}'")
    if args.json:
        _emit(result, True)
    else:
        ok = result.get("ok")
        print(f"[{'OK' if ok else 'FAIL'}] {result.get('probe')} "
              f"{result.get('from','')}->{result.get('to','')}")
        if "rtt_ms" in result:
            print(f"  loss={result.get('loss_percent')}%  "
                  f"rtt avg={result['rtt_ms']['avg']}ms")
        if result.get("probe") == "iperf3" and ok:
            print(f"  throughput sent={result.get('sent_mbps')}Mbps "
                  f"recv={result.get('received_mbps')}Mbps")
        if result.get("probe") == "curl":
            print(f"  http={result.get('http_code')} "
                  f"t={result.get('time_total_s')}s")
        if result.get("probe") == "counters":
            for n, d in result["nodes"].items():
                print(f"  {n} {d.get('iface')}: rx={d.get('rx')} tx={d.get('tx')}")
        if not ok and result.get("raw"):
            print(result["raw"])
        if result.get("error"):
            print(f"  error: {result['error']}")
    return 0 if result.get("ok", True) else 1


def cmd_fault(args) -> int:
    lab = _only_lab(args.lab)
    led = load_ledger(lab)
    if led is None:
        raise SystemExit(f"no such lab '{lab}'")
    # Apply the fault to the FIRST node's carrier-side iface. For wg/udp/filament
    # the overlay-bearing iface differs; we degrade the underlay where possible,
    # else the tun. We target node-a's tun by default (works for all carriers).
    nodes = led.nodes()
    a = list(nodes.keys())[0]
    ns = nodes[a]["netns"]
    # target the carrier's DATA-PATH iface (tun/veth/wg), recorded at `up`; fall
    # back to the tun for older ledgers.
    iface = nodes[a].get("datapath_iface", nodes[a]["tun"])
    if args.kind == "clear":
        fault_prim.clear(led, ns, iface)
        _emit({"lab": lab, "fault": "cleared"}, args.json,
              f"fault cleared on {ns}/{iface}")
        return 0
    params = {}
    if args.value:
        # crude key=val parser: e.g. percent=20 or delay=80ms
        for tok in args.value:
            if "=" in tok:
                k, v = tok.split("=", 1)
                params[k] = v
            else:
                params["value"] = tok
    # map a bare positional value to the natural param for the fault kind
    if "value" in params:
        v = params.pop("value")
        params[{"loss": "percent", "latency": "delay",
                "bandwidth": "rate"}.get(args.kind, "value")] = v
    desc = fault_prim.apply(led, ns, iface, args.kind, **params)
    _emit({"lab": lab, "fault": desc, "ns": ns, "iface": iface}, args.json,
          f"fault applied: {desc} on {ns}/{iface}")
    return 0


def cmd_doctor(args) -> int:
    rep = doctor.run(link=args.link)
    if args.json:
        _emit([{"name": c.name, "ok": c.ok, "fatal": c.fatal,
                "detail": c.detail, "hint": c.hint} for c in rep.checks], True)
    else:
        print(f"lab doctor (link={args.link}):")
        print(doctor.format_report(rep))
    return 0 if rep.ok() else 1


def cmd_list(args) -> int:
    from labkit.topology import TOPO_DIR
    topos = sorted(p.stem for p in TOPO_DIR.glob("*.y*ml")) + \
        sorted(p.stem for p in TOPO_DIR.glob("*.json"))
    labs = list_labs()
    if args.json:
        _emit({"topologies": topos, "running": labs}, True)
    else:
        print("topologies:", ", ".join(topos) or "(none)")
        print("running labs:", ", ".join(labs) or "(none)")
    return 0


def cmd_compose(args) -> int:
    """Inspect/wire individual primitives — currently a topology+plan preview so
    a user (or the skill) can see exactly what `up` will create, before doing it.
    """
    topo = load_topology(args.topology)
    led = Ledger(topo.name + "-preview")  # not saved
    ctx = LinkContext(topo, led, args.link or topo.link.provider, "none",
                      engine.log_dir_for(topo.name))
    plan = {
        "topology": topo.name, "link": ctx.provider,
        "overlay_subnet": topo.subnet,
        "transport_subnet": topo.link.transport_subnet,
        "nodes": {ep.node: {"netns": ep.ns, "overlay_ip": ep.overlay_ip,
                            "underlay_ip": ep.underlay_ip,
                            "tun": ctx.tun_iface(ep)} for ep in ctx.endpoints},
        "primitives": ["tun", f"link={ctx.provider}", "route",
                       f"crypto={engine._default_crypto(ctx.provider)}"],
    }
    _emit(plan, args.json, json.dumps(plan, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lab", description="filament networking dev-lab (lab as code).")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("up", help="realize a topology")
    up.add_argument("topology")
    up.add_argument("--link", choices=["pipe", "veth", "udp", "wg", "filament"],
                    help="override the link provider")
    up.add_argument("--crypto", choices=["none", "wg-noise", "dtls"])
    up.add_argument("--no-doctor", action="store_true",
                    help="skip preflight (not recommended)")
    up.set_defaults(func=cmd_up)

    dn = sub.add_parser("down", help="destroy a lab (robust teardown)")
    dn.add_argument("lab", nargs="?")
    dn.add_argument("--all", action="store_true",
                    help="tear down every lab + sweep stray namespaces")
    dn.add_argument("--purge-logs", action="store_true")
    dn.set_defaults(func=cmd_down)

    st = sub.add_parser("status", help="show lab(s) status")
    st.add_argument("lab", nargs="?")
    st.set_defaults(func=cmd_status)

    pr = sub.add_parser("probe", help="drive + measure across the tunnel")
    pr.add_argument("kind", choices=["ping", "iperf", "curl", "counters"])
    pr.add_argument("lab", nargs="?")
    pr.add_argument("--count", type=int, default=5)
    pr.add_argument("--seconds", type=int, default=5)
    pr.set_defaults(func=cmd_probe)

    fa = sub.add_parser("fault", help="induce loss/latency/bandwidth/stall")
    fa.add_argument("kind",
                    choices=["loss", "latency", "bandwidth", "stall", "clear"])
    fa.add_argument("lab", nargs="?")
    fa.add_argument("value", nargs="*",
                    help="param(s): e.g. 20  or  delay=80ms  or  rate=1mbit")
    fa.set_defaults(func=cmd_fault)

    dc = sub.add_parser("doctor", help="preflight checks")
    dc.add_argument("--link", default="pipe",
                    choices=["pipe", "veth", "udp", "wg", "filament"])
    dc.set_defaults(func=cmd_doctor)

    sub.add_parser("list", help="list topologies + running labs").set_defaults(
        func=cmd_list)

    co = sub.add_parser("compose", help="preview the primitive wiring for a topology")
    co.add_argument("topology")
    co.add_argument("--link", choices=["pipe", "veth", "udp", "wg", "filament"])
    co.set_defaults(func=cmd_compose)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
