"""topology.py — declarative topology-as-code (the netlab-inspired core).

A topology is a small YAML (or JSON) file describing NODES + LINKS + per-node
params, with DEFAULTS and per-node OVERRIDES. It is PROVIDER-AGNOSTIC: the link
says "connect node a and node b on subnet X"; HOW that carriage happens (pipe /
udp / wg / filament) is chosen at ``up`` time via ``--link`` (or the link's own
``provider:`` field), exactly the netlab provider split.

To stay dependency-light we parse YAML with a tiny built-in subset parser (no
PyYAML needed) that handles the shapes our schema uses; if PyYAML happens to be
installed we use it for robustness. JSON topologies are always accepted.

Schema (see lab/resources/topology-schema.md for the full reference)::

    name: two-nodes              # lab name (also the ledger key)
    subnet: 10.50.0.0/24         # the tunnel/overlay subnet (TUN addresses)
    defaults:                    # applied to every node unless overridden
      mtu: 1380
    nodes:
      a: { addr: 10.50.0.1 }     # per-node overrides merge over defaults
      b: { addr: 10.50.0.2 }
    link:
      provider: pipe             # default carrier (overridable by `up --link`)
      endpoints: [a, b]          # exactly two nodes for now
      transport_subnet: 10.77.0.0/24   # underlay addrs (veth/udp/wg)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


TOPO_DIR = Path(__file__).resolve().parent.parent / "topologies"


@dataclass
class Node:
    name: str
    addr: str                       # overlay (TUN) IP, no prefix
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Link:
    provider: str
    endpoints: List[str]
    transport_subnet: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Topology:
    name: str
    subnet: str
    nodes: List[Node]
    link: Link
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def prefixlen(self) -> int:
        return int(self.subnet.split("/")[1])

    def node(self, name: str) -> Node:
        for n in self.nodes:
            if n.name == name:
                return n
        raise KeyError(f"no node named {name!r} in topology {self.name!r}")


# --------------------------------------------------------------- YAML subset --

def _parse_yaml(text: str) -> Dict[str, Any]:
    """Parse the small YAML subset our topologies use, stdlib-only.

    Prefers PyYAML if available. Otherwise handles: nested mapping by 2-space
    indentation, ``key: value`` scalars, inline flow maps ``{a: 1, b: 2}`` and
    flow lists ``[a, b]``, and block lists (``- item``). This is deliberately
    small — enough for our schema, not a general YAML engine.
    """
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        pass

    def coerce(v: str) -> Any:
        v = v.strip()
        if v == "" or v == "~" or v == "null":
            return None
        if v in ("true", "True"):
            return True
        if v in ("false", "False"):
            return False
        if (v.startswith('"') and v.endswith('"')) or \
           (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        try:
            return int(v)
        except ValueError:
            pass
        try:
            return float(v)
        except ValueError:
            pass
        return v

    def parse_flow(v: str) -> Any:
        v = v.strip()
        if v.startswith("{") and v.endswith("}"):
            body = v[1:-1].strip()
            d: Dict[str, Any] = {}
            if body:
                for part in _split_top(body):
                    k, _, val = part.partition(":")
                    d[k.strip()] = parse_flow(val)
            return d
        if v.startswith("[") and v.endswith("]"):
            body = v[1:-1].strip()
            return [parse_flow(x) for x in _split_top(body)] if body else []
        return coerce(v)

    def _split_top(s: str) -> List[str]:
        """Split on top-level commas (ignore commas inside nested {} / [])."""
        out, depth, cur = [], 0, ""
        for ch in s:
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
            if ch == "," and depth == 0:
                out.append(cur)
                cur = ""
            else:
                cur += ch
        if cur.strip():
            out.append(cur)
        return out

    # Build a tree from indentation.
    lines = [ln.rstrip() for ln in text.splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]

    def block(idx: int, indent: int):
        result: Any = None
        i = idx
        while i < len(lines):
            ln = lines[i]
            cur_indent = len(ln) - len(ln.lstrip())
            if cur_indent < indent:
                break
            if cur_indent > indent:
                i += 1
                continue
            stripped = ln.strip()
            if stripped.startswith("- "):
                if result is None:
                    result = []
                item = stripped[2:].strip()
                if item.startswith(("{", "[")):
                    result.append(parse_flow(item))
                elif ":" in item and not item.startswith(("{", "[")):
                    # inline mapping as a list element: "- key: val"
                    sub, ni = block(i, cur_indent + 2)
                    # re-handle the leading key on this same line
                    k, _, v = item.partition(":")
                    base = {k.strip(): parse_flow(v) if v.strip() else None}
                    if isinstance(sub, dict):
                        base.update(sub)
                    result.append(base)
                    i = ni
                    continue
                else:
                    result.append(coerce(item))
                i += 1
                continue
            key, _, val = stripped.partition(":")
            key = key.strip()
            if result is None:
                result = {}
            if val.strip():
                result[key] = parse_flow(val)
                i += 1
            else:
                child, ni = block(i + 1, cur_indent + 2)
                result[key] = child if child is not None else {}
                i = ni
        return result, i

    tree, _ = block(0, 0)
    return tree or {}


# ------------------------------------------------------------------- loading --

def load_text(text: str, fmt: str = "yaml") -> Dict[str, Any]:
    if fmt == "json":
        return json.loads(text)
    return _parse_yaml(text)


def from_dict(d: Dict[str, Any]) -> Topology:
    name = d.get("name") or "lab"
    subnet = d.get("subnet") or "10.50.0.0/24"
    defaults = d.get("defaults") or {}

    nodes: List[Node] = []
    raw_nodes = d.get("nodes") or {}
    if isinstance(raw_nodes, dict):
        items = raw_nodes.items()
    else:  # list form: [{name: a, addr: ...}, ...]
        items = [(n.get("name"), n) for n in raw_nodes]
    for nm, params in items:
        params = dict(params or {})
        merged = {**defaults, **params}
        addr = merged.get("addr")
        if not addr:
            raise ValueError(f"node {nm!r} has no `addr`")
        nodes.append(Node(name=str(nm), addr=str(addr), params=merged))

    lk = d.get("link") or {}
    link = Link(
        provider=lk.get("provider", "pipe"),
        endpoints=[str(x) for x in (lk.get("endpoints") or [n.name for n in nodes][:2])],
        transport_subnet=lk.get("transport_subnet", "10.77.0.0/24"),
        params={k: v for k, v in lk.items()
                if k not in ("provider", "endpoints", "transport_subnet")},
    )
    return Topology(name=name, subnet=subnet, nodes=nodes, link=link, raw=d)


def resolve_path(topo: str) -> Path:
    """Resolve a topology name or path to a file under topologies/ (or cwd)."""
    p = Path(topo)
    if p.exists():
        return p
    for ext in ("", ".yml", ".yaml", ".json"):
        cand = TOPO_DIR / f"{topo}{ext}"
        if cand.exists():
            return cand
    raise FileNotFoundError(
        f"topology {topo!r} not found (looked in {TOPO_DIR} and as a path)")


def load(topo: str) -> Topology:
    path = resolve_path(topo)
    fmt = "json" if path.suffix == ".json" else "yaml"
    return from_dict(load_text(path.read_text(), fmt))
