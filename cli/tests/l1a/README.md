# L1-a PAKE first-pairing gates

Standalone validation for the SPAKE2 first-pairing change (spec
`docs/L1-pake-protocol.md` §10). These run on **port 8093** (a private fixture
backend), independent of the main `gates.sh` suite (which pins 8077).

## Prerequisites

```sh
# build the CLI + shared pake crate (incl. the adversary + native_side bins)
( cd ../.. && cargo build --release )
( cd ../../../pake && cargo build --release --bins )
# regenerate + commit the browser WASM if pake/src changed
( cd ../../../pake && ./build-wasm.sh )
# start the fixture backend on 8093 (eventlet, claim-limit pinned)
( cd ../../../backend && PORT=8093 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 python app.py & )
```

The scripts assume the venv path used during development; adjust `BIN`/`PY`/
paths at the top of each script for your environment.

## The seven gates

| # | script | property |
|---|--------|----------|
| 1 mutual-key        | `gate1_mutual_key.sh`    | two real `filament pair` procs, same code → identical pinned secret; confirmation passes |
| 2 adversarial (NEG) | `cargo run --bin adversary` (in `pake/`) | element-MITM / a=fingerprint-rewrite / caps-rewrite all DETECTED → abort, zero secret (A/B numbers) |
| 3 wrongpw-burns     | `gate3_wrongpw_burn.sh`  | wrong password REFUSED, nothing stored, nameplate BURNED, no silent retry |
| 4 browser↔cli       | `node gate4_interop.mjs` | committed browser WASM and native CLI derive the SAME secret + mutually confirm |
| 5 caps deny-default | `cargo test capability_deny_by_default` (in `cli/`) | empty caps refuse a gated action; "transfer" is the L0 baseline; not escalatable |
| 6 downgrade-refused | `gate6_downgrade.sh`     | a v:2-stripping server (FIL_FORCE_V1) is refused; no v2 path stores a server-readable secret |
| 7 no-regression     | `gate7_noregression.sh`  | vanilla send/recv still transfers; remembered v2 devices reconnect unchanged |
| 9 transfer-pake     | `gate9_transfer_pake.sh` | `send --code` / `recv <code>` run the SHARED ephemeral SPAKE2 ceremony, transfer byte-exact, and persist NO secret (discarded after auth). Parameterized by `BIN`/`SERVER`. |

Backend crypto + the relay-blind NEGATIVE assertion (words never reach the
server): `python -m unittest backend.tests.test_pair_codes`.
Shared SPAKE2 crate unit tests (incl. reflection-rejected): `cargo test` in `pake/`.

Gates 6 and 7 restart the 8093 backend; gate 6 needs `FIL_FORCE_V1`.
