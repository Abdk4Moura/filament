"""primitive 5 — crypto: a declarative selector for the link's confidentiality.

The lab does not roll its own crypto. Instead ``crypto`` records WHICH layer
provides confidentiality for a given link, so a topology states its security
model explicitly and the engine can validate the choice against the carrier:

  none     — rely on the carrier's own encryption (or none at all). Correct for
             the `filament` link: filament's data channel is already DTLS-SRTP
             and pair-proof authenticated, so layering WG on top is redundant.
             Also the honest label for the bare `pipe`/`udp` baselines.
  wg-noise — WireGuard's Noise_IKpsk2 handshake + ChaCha20-Poly1305. This is what
             the `wg` carrier supplies natively; selecting it on a non-wg carrier
             is an error (we don't have a standalone Noise implementation).
  dtls     — DTLS (e.g. the filament channel). A label for "the carrier already
             gives us DTLS"; not independently established by the lab.

Interface:
    validate(crypto, provider) -> None     # raise on an incoherent combination
    describe(crypto) -> str
"""

from __future__ import annotations

VALID = {"none", "wg-noise", "dtls"}

# Which crypto each carrier can actually provide / is coherent with.
_COHERENT = {
    "pipe":     {"none"},
    "udp":      {"none"},
    "wg":       {"wg-noise"},
    "filament": {"none", "dtls"},  # the channel is DTLS; `none` = lean on it
}


def validate(crypto: str, provider: str) -> None:
    if crypto not in VALID:
        raise ValueError(
            f"unknown crypto {crypto!r}; choose one of {sorted(VALID)}")
    allowed = _COHERENT.get(provider, VALID)
    if crypto not in allowed:
        raise ValueError(
            f"crypto={crypto!r} is incoherent with link provider {provider!r}; "
            f"this carrier supports {sorted(allowed)}. (The lab does not roll its "
            f"own Noise/DTLS — the carrier must supply it.)")


def describe(crypto: str) -> str:
    return {
        "none": "no lab-added crypto (lean on the carrier or run in the clear)",
        "wg-noise": "WireGuard Noise_IKpsk2 + ChaCha20-Poly1305 (carrier-native)",
        "dtls": "DTLS provided by the carrier (e.g. filament's data channel)",
    }.get(crypto, crypto)
