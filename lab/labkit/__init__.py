"""labkit — the filament networking dev-lab engine.

A small, dependency-light (Python stdlib + iproute2/wg/tc/iperf3) "lab as code"
engine inspired by netlab (https://netlab.tools) but with none of its heavy deps
(no Ansible, no containers, no cloud). Nodes are Linux network namespaces on this
one host; links between them are pluggable providers.

Everything the lab creates is recorded in a per-lab state ledger under
``lab/.state/`` so teardown is robust even after a partial/failed ``up``.

Modules:
  state   — the resource ledger (what we created, so we can destroy it)
  netns   — thin, audited wrappers over ``ip netns`` / ``ip link`` / ``tc``
  engine  — realize/destroy a declarative topology (the ``up``/``down`` core)
  doctor  — preflight: root, kernel modules, required tools
  cli     — the argparse front-end behind the ``lab`` command
"""

__all__ = ["state", "netns", "engine", "doctor", "cli"]
