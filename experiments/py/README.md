# filament_lab — a controllable Python peer for the Filament control plane

A reusable library + interactive driver that makes the Filament
signaling / pairing / discovery / transport-offer flow **scriptable, inspectable,
and step-into-able**, and that **interoperates with the real Rust `filament`
binary on the same wire**.

The Rust transport keeps failing on cross-machine signaling races (late-join
presence misses, fire-once transport-offers). A controllable Python peer lets us
reproduce and experiment with those deterministically, and acts as a reference
oracle to diff against the Rust.

> Scope: this is the **control plane** (signaling + crypto + the offer/pairing
> protocol). The direct QUIC data transport (aioquic) is intentionally **not**
> implemented — the control plane is where the bugs live.

## Layout

| file | what |
|------|------|
| `filament_lab/crypto.py` | `channel_of`, `proof_for`, `norm_code`/`split_code`, SPAKE2 ceremony + confirm-MAC, `secret_from_k` — byte-mirrors of `cli/src/main.rs` + `pake/src/lib.rs` |
| `filament_lab/signaling.py` | `Signaling`: python-socketio client over the full event contract (join/welcome, subscribe/known-peer, sync/synced, signal, pair-*) with callbacks + recorded state |
| `filament_lab/peer.py` | `Peer`: a known-device peer that subscribes to `channel_of(secret)`, tracks known-peers, does the transport-offer exchange, and carries the fault knobs |
| `filament_lab/driver.py` | scriptable scenarios (`watch` / `discover` / `late-join`) **and** an interactive REPL |
| `test_crypto.py` | 7 crypto-fidelity tests (no pytest dep) |
| `run_interop.sh` | one command: boots the fixture backend, plants a device, starts real `filament up`, runs a Python scenario |

## Setup

```bash
VENV=/root/.claude/jobs/330c2366/tmp/venv      # has socketio/flask/eventlet
$VENV/bin/pip install -r requirements.txt       # adds websocket-client, spake2, requests
```

**The handshake fix.** The seed `probe.py` failed with `One or more namespaces
failed to connect`. Cause: it forced `transports=["websocket"]` while the
`websocket-client` package was absent, so no transport had an implementation —
*not* a Socket.IO/Engine.IO protocol-version mismatch (python-socketio 5.x already
speaks the EIO4/SIO5 the Flask-SocketIO fixture uses). Installing
`websocket-client` resolves it. We default to the websocket transport because the
eventlet fixture lags delivery of server-initiated emits (the `welcome`) over
long-poll. Note: `welcome` is the **response to `join`**, not to bare connect.

## Run the fixture backend

```bash
cd backend && PORT=8099 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
  /root/.claude/jobs/330c2366/tmp/venv/bin/python app.py
```

## Interop, one command

```bash
./run_interop.sh discover      # or: late-join | watch
```

This plants `devices.json` with a shared secret, starts the **real release
binary** `filament up` (with `FILAMENT_L2=1` so it emits transport-offers),
then runs the Python peer as the late subscriber.

## The REPL (step in by hand)

```bash
$VENV/bin/python -m filament_lab.driver --secret <hex> repl
> peers                      # known-peers seen on our channels
> offer <sid> 10.0.0.5:5000  # send a transport-offer
> sig <sid> {"type":"x"}     # arbitrary signal payload
> raw subscribe {"channels":["<64hex>"]}   # emit any event (fault injection)
> fault withhold 1           # withhold | delay <s> | duplicate <n> | reorder 1
> policy offer               # auto-offer on discovery (default: observe)
> tape                       # dump the recorded event tape
> quit
```

`--secret` and `--channel` are both repeatable (multiple devices / raw channels).

## Interop demonstrations (verified)

All against the local fixture backend + the release binary
`cli/target/release/filament`.

**1. Python connects + receives `welcome`**

```
[  0.006s] connect        transport=websocket
[  0.006s] -> join        room=pylab-room uid=uid-pylab
[  0.008s] welcome        id=gVYz95Q1kw-IKkq0AAAD peers=[]
[  0.010s] subscribe-ack  {"ok": true, "n": 1}
```

**2. Python ↔ Rust discovery + transport-offer round-trip** (`discover`)

`channel_of(secret)` is **byte-identical** to the binary: a planted secret yields
`channel d6b6e37400ac` in both `filament devices` and `crypto.channel_of(...)`.
On the shared channel:

```
[0.018s] KNOWN-PEER  id=Tzd… name=rust-up uid=cli-r-… chan=d6b6e37400ac   # we see Rust
[0.019s] OFFER-OUT   to=Tzd… addrs=['127.0.0.1:59999']                    # our offer
[0.061s] OFFER-IN    from=Tzd… v=1 addrs=['165.22.207.231:40186',         # Rust's real
                     '[2a03:b0c0:2:f0:0:1:a283:b001]:40186','127.0.0.1:40186']  candidates
```

Both `transport-offer`s crossed — Rust replied with its **real** gathered
candidates (public v4, v6, loopback). Discovery is mutual (`known-peer` both ways).

**3. The late-join experiment** (`late-join`) — Python subscribes *after* `up`

```
"a_known_peer_received": true,
"b_offer_received":       true,
"verdict": "OK: known-peer AND transport-offer both reached the late subscriber"
```

**Finding (oracle result):** at the **channel-presence layer the late-join is NOT
a miss.** The server's `_do_subscribe` (`backend/signaling.py:509`) emits
`known-peer` **symmetrically** — to both the newcomer and the already-present
peer — so a late subscriber reliably learns about an existing peer, and the Rust
acceptor **re-fires** its transport-offer on each new `KnownPeer` (note the fresh
UDP port per run). So the cross-machine "late-join presence miss" the Rust suffers
is **not** in the signaling subscribe path; it lives downstream in the
WebRTC/QUIC offer-race timing (`cli/src/l2.rs:437-505` — `direct_racing` ignores
re-sends; a late initiator that misses the *first* offer then drops the rest).
The fault knobs below let you reproduce exactly that class of failure on demand.

**4. Fault injection is deterministic** (e.g. `fault withhold`)

```
[0.011s] DISCOVERED     device='dev0' sid=Tzd…
[0.011s] OFFER-WITHHELD to=Tzd… (fault: withhold)
  peer Tzd… offer_sent=False offer_in=True
```

The Python peer discovers Rust and receives its offer, but sends **none** — a
deterministic reproduction of the "offer never sent" half of the race.

## Real vs stubbed

| component | status |
|-----------|--------|
| Signaling client (connect/join/subscribe/sync/signal/pair-*) | **real**, verified vs fixture |
| `channel_of`, `proof_for`, `norm_code`, `split_code` | **real**, wire-faithful (channel_of cross-checked vs binary) |
| transport-offer build/parse + exchange | **real**, round-tripped with the binary |
| SPAKE2 pairing ceremony + confirm-MAC | **real library**, unit-tested **python↔python only** — *not* Rust-wire-verified, because the Rust confirm-MAC folds in WebRTC DTLS fingerprints (`main.rs:1163`) that only exist with a live WebRTC peer |
| `pair-proof` MAC | **real** (satisfies the acceptor's gate); rides the data channel in the real flow, so emitted but not transport-delivered here |
| direct QUIC data transport (aioquic) | **stubbed / out of scope** — control plane only |

## Tests

```bash
$VENV/bin/python test_crypto.py        # 7 fidelity tests
```
