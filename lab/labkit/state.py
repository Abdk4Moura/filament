"""state.py — the lab's resource ledger.

THE central safety mechanism. Every host-level resource the lab creates
(a netns, a veth, a tun, a wg iface, a spawned PID, a tc qdisc) is appended to a
per-lab JSON ledger BEFORE/AS it is created. Teardown reads the ledger and
destroys resources in reverse order, so ``down`` cleans up everything even after
a crashed or partial ``up`` — no leaked namespaces or interfaces.

The ledger lives at ``lab/.state/<lab>.json``. It is intentionally
human-readable: if the engine ever dies mid-flight you can read the file and see
exactly what to clean up by hand (or just run ``lab down <lab>`` again — teardown
is idempotent).

Resource kinds (the ``kind`` field), destroyed in reverse-insertion order:
  pid    — a process we spawned (killed by PID, then SIGKILL if it lingers)
  tc     — a tc qdisc we added inside a netns iface (deleted via `tc qdisc del`)
  wg     — a wireguard iface inside a netns (deleted with the iface)
  tun    — a tun iface inside a netns
  veth   — a veth pair (deleting one end deletes both)
  netns  — a network namespace (deleting it frees everything still inside it)
  file   — a scratch file/dir to unlink (keys, sockets)

Because deleting a netns frees every iface still inside it, netns deletion is the
backstop: even if an inner-iface delete fails, removing the namespace reclaims
it. We still record inner resources so PIDs/tc/files outside the netns are caught.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


# lab/.state/ — sibling of this package's parent (the lab/ root).
STATE_DIR = Path(__file__).resolve().parent.parent / ".state"


def _ledger_path(lab: str) -> Path:
    return STATE_DIR / f"{lab}.json"


class Ledger:
    """A mutable, append-on-write record of one lab's host resources."""

    def __init__(self, lab: str):
        self.lab = lab
        self.path = _ledger_path(lab)
        self.data: Dict[str, Any] = {
            "lab": lab,
            "created": time.time(),
            "topology": None,
            "link": None,
            "resources": [],   # ordered; teardown walks this in reverse
            "nodes": {},       # node-name -> {netns, addr, ...} (for probe/status)
            "meta": {},        # free-form: ports, paths, link-specific bookkeeping
        }
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                # Corrupt ledger: keep the fresh skeleton but don't lose the file.
                pass

    # ---- persistence ----------------------------------------------------

    def save(self) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, indent=2))
        os.replace(tmp, self.path)  # atomic — a crash never leaves a half file

    def remove(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def exists(self) -> bool:
        return self.path.exists()

    # ---- recording resources -------------------------------------------

    def add(self, kind: str, name: str, **extra: Any) -> None:
        """Record a created resource. Call this AS you create it, then save().

        Idempotent on (kind, name): re-adding the same resource (a re-run of an
        idempotent ``up``) updates rather than duplicates the entry.
        """
        for r in self.data["resources"]:
            if r["kind"] == kind and r["name"] == name:
                r.update(extra)
                self.save()
                return
        entry = {"kind": kind, "name": name}
        entry.update(extra)
        self.data["resources"].append(entry)
        self.save()

    def resources(self) -> List[Dict[str, Any]]:
        return list(self.data["resources"])

    def resources_reversed(self) -> List[Dict[str, Any]]:
        return list(reversed(self.data["resources"]))

    def forget(self, kind: str, name: str) -> None:
        self.data["resources"] = [
            r for r in self.data["resources"]
            if not (r["kind"] == kind and r["name"] == name)
        ]
        self.save()

    # ---- node / meta bookkeeping ---------------------------------------

    def set_node(self, name: str, **fields: Any) -> None:
        self.data["nodes"].setdefault(name, {}).update(fields)
        self.save()

    def node(self, name: str) -> Dict[str, Any]:
        return self.data["nodes"].get(name, {})

    def nodes(self) -> Dict[str, Any]:
        return dict(self.data["nodes"])

    def set_meta(self, key: str, value: Any) -> None:
        self.data["meta"][key] = value
        self.save()

    def meta(self, key: str, default: Any = None) -> Any:
        return self.data["meta"].get(key, default)


def list_labs() -> List[str]:
    """Names of all labs with a ledger on disk (running or partially-up)."""
    if not STATE_DIR.exists():
        return []
    return sorted(p.stem for p in STATE_DIR.glob("*.json"))


def load(lab: str) -> Optional[Ledger]:
    """Load an existing ledger, or None if this lab was never brought up."""
    if not _ledger_path(lab).exists():
        return None
    return Ledger(lab)
