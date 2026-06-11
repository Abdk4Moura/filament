"""primitive 7 — probe: drive + measure across the tunnel.

Runs traffic from one node to another's OVERLAY address and emits machine-readable
(JSON) results, so the same probe is comparable across `pipe`/`wg`/`filament`.

Probes:
  ping  — reachability + RTT (parses ping summary). Retries, because the
          filament carrier's data channel can take a few seconds to come up.
  iperf3 — throughput: starts an iperf3 -s in the destination netns, runs the
          client in the source netns, returns the parsed JSON.
  curl  — application reachability: starts a tiny HTTP server in the dest netns,
          curls it from the source over the overlay.
  counters — TUN/iface packet+byte counters for both endpoints.

All probes run via ``ip netns exec`` and target overlay IPs — never the host.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict

from labkit import netns
from labkit.state import Ledger


def _endpoints(ledger: Ledger):
    nodes = ledger.nodes()
    names = list(nodes.keys())
    if len(names) < 2:
        raise RuntimeError("lab has fewer than two nodes; cannot probe")
    a, b = names[0], names[1]
    return a, nodes[a], b, nodes[b]


def ping(ledger: Ledger, count: int = 5, retries: int = 8) -> Dict[str, Any]:
    a, na, b, nb = _endpoints(ledger)
    target = nb["overlay_ip"]
    ns = na["netns"]
    out = ""
    ok = False
    # Retry: the filament data channel may need a few seconds post-up.
    for attempt in range(retries):
        ok, out = netns.ping(ns, target, count=count)
        if ok:
            break
        time.sleep(1.5)
    result: Dict[str, Any] = {
        "probe": "ping", "from": a, "to": b, "target": target,
        "ok": ok, "attempts": attempt + 1,
    }
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received,"
                  r".*?(\d+(?:\.\d+)?)% packet loss", out, re.S)
    if m:
        result["transmitted"] = int(m.group(1))
        result["received"] = int(m.group(2))
        result["loss_percent"] = float(m.group(3))
    r = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", out)
    if r:
        result["rtt_ms"] = {"min": float(r.group(1)), "avg": float(r.group(2)),
                            "max": float(r.group(3)), "mdev": float(r.group(4))}
    result["raw"] = out.strip()
    return result


def iperf(ledger: Ledger, seconds: int = 5) -> Dict[str, Any]:
    import shutil
    if shutil.which("iperf3") is None:
        return {"probe": "iperf3", "ok": False,
                "error": "iperf3 not installed (apt-get install -y iperf3)"}
    a, na, b, nb = _endpoints(ledger)
    target = nb["overlay_ip"]
    srv_ns, cli_ns = nb["netns"], na["netns"]

    srv_pid = netns.spawn(["iperf3", "-s", "-1", "-B", target], ns=srv_ns,
                          logfile=None)
    time.sleep(0.6)
    try:
        proc = netns.nsx(cli_ns, "iperf3", "-c", target, "-t", str(seconds),
                         "-J", check=False, timeout=seconds + 20)
        data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        sent = data.get("end", {}).get("sum_sent", {})
        recv = data.get("end", {}).get("sum_received", {})
        return {
            "probe": "iperf3", "from": a, "to": b, "target": target,
            "ok": proc.returncode == 0 and bool(sent),
            "sent_bps": sent.get("bits_per_second"),
            "received_bps": recv.get("bits_per_second"),
            "sent_mbps": round(sent.get("bits_per_second", 0) / 1e6, 3) if sent else None,
            "received_mbps": round(recv.get("bits_per_second", 0) / 1e6, 3) if recv else None,
            "retransmits": sent.get("retransmits"),
        }
    finally:
        netns.kill(srv_pid)


def curl(ledger: Ledger, port: int = 8080) -> Dict[str, Any]:
    import shutil
    if shutil.which("curl") is None:
        return {"probe": "curl", "ok": False, "error": "curl not installed"}
    a, na, b, nb = _endpoints(ledger)
    target = nb["overlay_ip"]
    srv_ns, cli_ns = nb["netns"], na["netns"]

    # tiny one-shot HTTP server bound to the dest overlay IP
    server_code = (
        "import http.server,socketserver;"
        f"socketserver.TCPServer(('{target}',{port}),"
        "http.server.SimpleHTTPRequestHandler).handle_request()"
    )
    srv_pid = netns.spawn(["python3", "-c", server_code], ns=srv_ns)
    time.sleep(0.6)
    try:
        proc = netns.nsx(cli_ns, "curl", "-s", "-o", "/dev/null",
                         "-w", "%{http_code} %{time_total}",
                         f"http://{target}:{port}/", check=False, timeout=20)
        parts = (proc.stdout or "").split()
        code = parts[0] if parts else ""
        t = float(parts[1]) if len(parts) > 1 else None
        return {"probe": "curl", "from": a, "to": b,
                "url": f"http://{target}:{port}/",
                "ok": code.startswith("2") or code.startswith("3") or code == "200",
                "http_code": code, "time_total_s": t}
    finally:
        netns.kill(srv_pid)


def counters(ledger: Ledger) -> Dict[str, Any]:
    out: Dict[str, Any] = {"probe": "counters", "nodes": {}}
    for name, info in ledger.nodes().items():
        ns, iface = info["netns"], info["tun"]
        p = netns.nsx(ns, "ip", "-s", "-j", "link", "show", iface, check=False)
        try:
            arr = json.loads(p.stdout)
            stats = arr[0].get("stats64", {})
            out["nodes"][name] = {
                "iface": iface,
                "rx": stats.get("rx", {}),
                "tx": stats.get("tx", {}),
            }
        except Exception:
            out["nodes"][name] = {"iface": iface, "raw": (p.stdout or "").strip()}
    return out
