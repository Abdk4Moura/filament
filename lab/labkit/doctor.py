"""doctor.py — preflight checks for the lab.

Run before any ``up`` (and on demand via ``lab doctor``). Verifies the host can
actually realize a topology with the requested link provider, and FAILS CLEARLY
with an install hint when it can't, rather than half-creating a broken lab.

Tiered: a `pipe` lab needs only root + iproute2 + /dev/net/tun; `wg` additionally
needs the wireguard datapath (kernel module or a userspace fallback); `filament`
needs the locally-built filament binary; probes need iperf3.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# The LOCALLY-BUILT filament binary (never the installed ~/.local/bin one, never
# the running daemon). Resolved relative to the repo root (lab/ is at repo root).
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FILAMENT_BIN = REPO_ROOT / "cli" / "target" / "release" / "filament"


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    fatal: bool = True          # a failed fatal check blocks the relevant `up`
    hint: str = ""


@dataclass
class Report:
    checks: List[Check] = field(default_factory=list)

    def add(self, c: Check) -> None:
        self.checks.append(c)

    def fatal_failures(self) -> List[Check]:
        return [c for c in self.checks if c.fatal and not c.ok]

    def ok(self) -> bool:
        return not self.fatal_failures()


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _kernel_wireguard() -> bool:
    """True if the kernel WireGuard datapath is available (module loads)."""
    try:
        r = subprocess.run(["modprobe", "wireguard"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False
        with open("/proc/modules") as f:
            return any(line.startswith("wireguard ") for line in f)
    except Exception:
        # /proc/modules may not list built-in modules; fall back to a probe.
        try:
            subprocess.run(["ip", "link", "add", "labwgprobe", "type", "wireguard"],
                           capture_output=True, timeout=10)
            subprocess.run(["ip", "link", "del", "labwgprobe"],
                           capture_output=True, timeout=10)
            return True
        except Exception:
            return False


def _userspace_wireguard() -> Optional[str]:
    for cand in ("wireguard-go", "boringtun"):
        if _have(cand):
            return cand
    return None


def run(link: str = "pipe", want_iperf: bool = True) -> Report:
    """Build a preflight report for the given link provider."""
    r = Report()

    # --- always required (any lab) ---
    r.add(Check("root", os.geteuid() == 0,
                detail="euid=%d" % os.geteuid(), fatal=True,
                hint="netns/tun/wg need root — re-run with sudo."))
    r.add(Check("iproute2 (ip)", _have("ip"), fatal=True,
                hint="install iproute2 (apt-get install -y iproute2)."))
    r.add(Check("tc (traffic control)", _have("tc"), fatal=False,
                hint="install iproute2; needed only for `lab fault`."))
    tun_ok = os.path.exists("/dev/net/tun")
    r.add(Check("/dev/net/tun", tun_ok, fatal=True,
                hint="load the tun module: modprobe tun (and ensure /dev/net/tun)."))
    r.add(Check("ping", _have("ping"), fatal=True,
                hint="install iputils-ping."))

    # --- probe tooling ---
    if want_iperf:
        r.add(Check("iperf3", _have("iperf3"), fatal=False,
                    hint="install iperf3 for throughput probes (apt-get install -y iperf3)."))
    r.add(Check("curl", _have("curl"), fatal=False,
                hint="install curl for the curl probe."))

    # --- link-specific ---
    if link == "wg":
        kern = _kernel_wireguard()
        usr = _userspace_wireguard()
        r.add(Check("wireguard datapath",
                    kern or usr is not None,
                    detail=("kernel" if kern else (usr or "none")),
                    fatal=True,
                    hint=("install wireguard-go or boringtun for a userspace "
                          "fallback, or load the kernel `wireguard` module.")))
        r.add(Check("wg (wireguard-tools)", _have("wg"), fatal=True,
                    hint="install wireguard-tools (apt-get install -y wireguard-tools)."))
    elif link == "filament":
        r.add(Check("filament (locally-built release binary)",
                    FILAMENT_BIN.exists(),
                    detail=str(FILAMENT_BIN), fatal=True,
                    hint="build it: (cd cli && cargo build --release)."))

    return r


def format_report(r: Report) -> str:
    lines = []
    for c in r.checks:
        mark = "OK " if c.ok else ("XX " if c.fatal else "-- ")
        line = f"  [{mark}] {c.name}"
        if c.detail:
            line += f"  ({c.detail})"
        lines.append(line)
        if not c.ok and c.hint:
            lines.append(f"          hint: {c.hint}")
    status = "PASS" if r.ok() else "FAIL"
    lines.append(f"  => preflight {status}")
    return "\n".join(lines)
