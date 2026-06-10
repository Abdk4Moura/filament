"""filament_lab — a controllable Python peer for the Filament control plane.

A reusable library (signaling + crypto + peer) and an interactive driver to
reproduce, inspect, and step into the signaling/pairing/discovery/offer flow,
and to interoperate with the real Rust `filament` binary on the same wire.
"""
from . import crypto, signaling  # noqa: F401

__all__ = ["crypto", "signaling", "peer", "driver"]
