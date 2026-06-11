"""netns.py — audited, namespace-scoped wrappers over iproute2 / tc / wg.

SAFETY INVARIANT (hard requirement): the lab NEVER mutates host networking.
Every interface/address/route/qdisc this module touches lives INSIDE a network
namespace the lab created. The only host-namespace operations are:
  * ``ip netns add/del <ns>``      — create/destroy a lab namespace
  * ``ip link add … type veth``    — create a veth pair, then IMMEDIATELY move
                                     BOTH ends into lab namespaces (a veth pair is
                                     born in the host ns; it must be relocated at
                                     once so it never carries host traffic).
Everything else is run via ``ip netns exec <ns> …`` and is confined to the ns.

All lab namespaces/ifaces are prefixed so they are unmistakable and so teardown
can find strays even without a ledger (the ``--all`` sweep). Names are also kept
<= 15 chars where the kernel requires it (iface names).
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from typing import List, Optional, Sequence, Tuple


# Prefixes — a lab-created resource is always recognizable by these.
NS_PREFIX = "lab-"          # network namespaces:   lab-<labname>-<node>
IFACE_PREFIX = "lab"        # ifaces (<=15 chars):  lab<short>


class CmdError(RuntimeError):
    def __init__(self, cmd: Sequence[str], rc: int, out: str, err: str):
        self.cmd = list(cmd)
        self.rc = rc
        self.out = out
        self.err = err
        super().__init__(
            f"command failed (rc={rc}): {' '.join(shlex.quote(c) for c in cmd)}\n{err.strip()}"
        )


def run(cmd: Sequence[str], check: bool = True, capture: bool = True,
        timeout: Optional[float] = 30.0) -> subprocess.CompletedProcess:
    """Run a command. Raises CmdError on non-zero exit when ``check``."""
    proc = subprocess.run(
        list(cmd),
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise CmdError(cmd, proc.returncode,
                       proc.stdout or "", proc.stderr or "")
    return proc


# --------------------------------------------------------------- namespaces --

def ns_name(lab: str, node: str) -> str:
    return f"{NS_PREFIX}{lab}-{node}"


def ns_exists(ns: str) -> bool:
    return os.path.exists(f"/var/run/netns/{ns}")


def ns_add(ns: str) -> None:
    """Create a netns (idempotent) and bring its loopback up."""
    if not ns_exists(ns):
        run(["ip", "netns", "add", ns])
    # lo must be up for in-ns loopback services (iperf3 -s binds, etc.)
    run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])


def ns_del(ns: str) -> None:
    """Delete a netns if present. Frees every iface still inside it."""
    if ns_exists(ns):
        run(["ip", "netns", "del", ns], check=False)


def nsx(ns: str, *args: str, check: bool = True, capture: bool = True,
        timeout: Optional[float] = 30.0) -> subprocess.CompletedProcess:
    """``ip netns exec <ns> <args...>`` — run a command INSIDE the namespace."""
    return run(["ip", "netns", "exec", ns, *args],
               check=check, capture=capture, timeout=timeout)


def list_lab_namespaces() -> List[str]:
    """All present namespaces with the lab prefix (the ``--all`` sweep source)."""
    d = "/var/run/netns"
    if not os.path.isdir(d):
        return []
    return sorted(n for n in os.listdir(d) if n.startswith(NS_PREFIX))


# lab iface name stems (used by the host-ns stray sweep). These only ever appear
# in the HOST namespace if a veth_add crashed after creating the pair but before
# relocating both ends — normally every lab iface lives inside a lab netns.
_LAB_IFACE_STEMS = ("labtun-", "labu-", "labwg-")


def list_stray_host_ifaces() -> List[str]:
    """Lab-prefixed ifaces left in the HOST netns (only from a crashed veth_add)."""
    p = run(["ip", "-o", "link", "show"], check=False)
    out = []
    for line in (p.stdout or "").splitlines():
        # format: "12: name@if13: <...>"
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@")[0]
        if any(name.startswith(s) for s in _LAB_IFACE_STEMS):
            out.append(name)
    return out


def del_host_iface(iface: str) -> None:
    run(["ip", "link", "del", iface], check=False)


# --------------------------------------------------------------------- veth --

def veth_add(a_if: str, a_ns: str, b_if: str, b_ns: str) -> None:
    """Create a veth pair and move each end into its namespace.

    Born in the host ns, then relocated AT ONCE so it never carries host
    traffic. Idempotent: if ``a_if`` already lives in ``a_ns`` we assume the pair
    is already placed and do nothing.
    """
    if iface_in_ns(a_if, a_ns):
        return
    # If a stale half exists in the host ns from a crashed run, clear it.
    run(["ip", "link", "del", a_if], check=False)
    run(["ip", "link", "add", a_if, "type", "veth", "peer", "name", b_if])
    run(["ip", "link", "set", a_if, "netns", a_ns])
    run(["ip", "link", "set", b_if, "netns", b_ns])


def iface_in_ns(iface: str, ns: str) -> bool:
    p = nsx(ns, "ip", "link", "show", iface, check=False)
    return p.returncode == 0


def addr_add(ns: str, iface: str, cidr: str) -> None:
    """Assign an address (idempotent — tolerates an already-assigned address)."""
    p = nsx(ns, "ip", "addr", "add", cidr, "dev", iface, check=False)
    err = (p.stderr or "")
    already = "File exists" in err or "Address already assigned" in err
    if p.returncode != 0 and not already:
        raise CmdError(["ip", "addr", "add", cidr, "dev", iface],
                       p.returncode, p.stdout, p.stderr)


def link_up(ns: str, iface: str) -> None:
    nsx(ns, "ip", "link", "set", iface, "up")


def route_add(ns: str, dest: str, dev: Optional[str] = None,
              via: Optional[str] = None) -> None:
    """Add a route INSIDE a namespace (idempotent)."""
    cmd = ["ip", "route", "add", dest]
    if via:
        cmd += ["via", via]
    if dev:
        cmd += ["dev", dev]
    p = nsx(ns, *cmd, check=False)
    if p.returncode != 0 and "File exists" not in (p.stderr or ""):
        raise CmdError(cmd, p.returncode, p.stdout, p.stderr)


# ---------------------------------------------------------------------- tun --

def tun_add(ns: str, iface: str) -> None:
    """Create a TUN iface inside a namespace (idempotent)."""
    if not iface_in_ns(iface, ns):
        nsx(ns, "ip", "tuntap", "add", "dev", iface, "mode", "tun")


# ----------------------------------------------------------------------- tc --

def tc_netem_add(ns: str, iface: str, **netem: str) -> None:
    """Attach a root netem qdisc to a namespaced iface (loss/delay/rate/etc).

    ``netem`` kwargs are passed through as ``key value`` pairs, e.g.
    ``loss="10%"``, ``delay="50ms"``, ``rate="1mbit"``. Replaces any existing
    root qdisc so re-applying a fault is idempotent.
    """
    args = ["tc", "qdisc", "replace", "dev", iface, "root", "netem"]
    for k, v in netem.items():
        args += [k, str(v)]
    nsx(ns, *args)


def tc_clear(ns: str, iface: str) -> None:
    nsx(ns, "tc", "qdisc", "del", "dev", iface, "root", check=False)


# ------------------------------------------------------------------ process --

def spawn(cmd: Sequence[str], ns: Optional[str] = None,
          logfile: Optional[str] = None, env: Optional[dict] = None) -> int:
    """Spawn a long-running process (optionally inside a namespace). Returns PID.

    The PID is what the ledger records; teardown signals it. stdout/stderr go to
    ``logfile`` so a crashed daemon leaves a diagnosable trail.
    """
    full = (["ip", "netns", "exec", ns] if ns else []) + list(cmd)
    out = open(logfile, "ab") if logfile else subprocess.DEVNULL
    e = dict(os.environ)
    if env:
        e.update(env)
    proc = subprocess.Popen(
        full, stdout=out, stderr=out, stdin=subprocess.DEVNULL,
        env=e, start_new_session=True,  # own process group -> clean kill
    )
    if logfile and out not in (subprocess.DEVNULL, None):
        out.close()
    return proc.pid


def kill(pid: int, grace: float = 2.0) -> None:
    """SIGTERM the process group, then SIGKILL after a grace period."""
    if not _pid_alive(pid):
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    deadline = time.time() + grace
    while time.time() < deadline:
        if not _pid_alive(pid):
            return
        time.sleep(0.05)
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but not ours to signal (shouldn't happen as root)


def pid_alive(pid: int) -> bool:
    """Public liveness check (status/probe use this)."""
    return _pid_alive(pid)


# ------------------------------------------------------------- diagnostics --

def ping(ns: str, dest: str, count: int = 3, timeout_s: int = 2) -> Tuple[bool, str]:
    """Ping ``dest`` from inside ``ns``. Returns (ok, raw_output)."""
    p = nsx(ns, "ping", "-c", str(count), "-W", str(timeout_s), dest,
            check=False, timeout=count * (timeout_s + 1) + 5)
    return (p.returncode == 0, (p.stdout or "") + (p.stderr or ""))
