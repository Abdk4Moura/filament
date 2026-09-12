# libfilament: the ideas, usable without the product

> Status: direction agreed 2026-08-27. Partly built. This is the map, and the
> rule for deciding what may leave the CLI.

## The goal

Someone should be able to build on filament's ideas without adopting filament.
Not "vendor the CLI and shell out to it" — take the piece they need, as a crate,
with a public API and no obligation to bring the rest.

That is not a rewrite. Nine crates exist now: the trust layer was already out
(`filament-cap`, `filament-id`, `filament-pair`, `authkeys-managed`,
`secret-write`), and `filament-transfer`, `filament-proto`, `filament-overlay`
and `filament-fleet` followed. What is left in the CLI is `Conn` and the
event loop.

## Why it is worth doing, from this repo's own history

The argument is not tidiness. It is that duplicated concepts have repeatedly
produced bugs in one copy and not the other:

- The fleet identity handshake was written twice, inline, once in the daemon's
  receive loop and once in `send_cmd`. FOUR bugs came out of the divergence,
  including a misdelivery, and every one of them was the same shape: state
  describing "the peer", stored as a single value, on a channel that carries
  every sibling. The daemon's copy had it right. The sender's did not.
- The close-reason hole was found and FIXED for `mount`, and survived in `pty`,
  because nobody walked the other copy. The contemporary record is preserved in
  [`archived work-state record`](archive/handoffs/WORK-STATE-2026-09-03.md).
- `main.rs` is ~22,400 lines and hand-writes the peer event loop EIGHT times.

  CORRECTION (2026-08-27): an earlier version of this line said the eight were
  copies of each other. They are not, and the difference matters for what to do
  about them. Measured, the eight `Ev::ChannelReady` arms are 5, 8, 12, 26, 39,
  88, 133 and 294 lines: they share a PROLOGUE and then diverge genuinely, because
  they belong to different commands. So the duplication to remove is the shared
  prologue and the handful of near-identical whole handlers (the two enrollment
  arms differ only in whether they print a line), not the loops wholesale.

  The prologue is now `Conn::mark_ready`, six call sites collapsed into one. The
  rest of the unification waits on splitting `Conn`.

A module boundary is not decoration here. It is the thing that makes a whole
class of bug unwritable.

## The rule for what may leave

`filament-cap`'s header states it well and the same test applies everywhere: the
reusable, host-independent piece leaves; the ORCHESTRATION stays, because it is
bound to the host, the filesystem, or the event loop. The extracted crate must
never call back into the CLI, so there is no cycle.

Concretely, a thing can leave when it has no opinion about:

- how a peer was found, authenticated, or named,
- where files live on this machine,
- how anything is rendered to a terminal.

`pwrite_at` failed that last test until today: it printed a short-write
diagnostic to stderr from inside the byte-writing primitive. It now RETURNS the
iteration count and the caller decides whether to report it. That is the shape of
every remaining extraction.

## Decomposition

Done:

| crate | what it owns |
|---|---|
| `filament-cap` | capability tokens, delegation ceilings, offline evaluation |
| `filament-id` | device identity |
| `filament-pair` | the pairing ceremony (PAKE) |
| `secret-write` | writing secrets to disk safely |
| `filament-transfer` | out-of-order reassembly, untrusted names, short-write-safe writes |
| `filament-proto` | the wire vocabulary + the pure ceremony decisions |
| `filament-overlay` | self-certifying addresses, link-bound announcements |
| `filament-fleet` | the admission ceremony + the per-peer session |
| `filament-transport` | the ladder: signalling, WebRTC, authenticated direct QUIC |

Next:

3-DONE. **`filament-transport`** — the `Transport` trait and the ladder beneath it
   (direct QUIC, WebRTC, relay). The piece with the most standalone value: "an
   authenticated byte pipe to a peer behind NAT, that fails over".

   MEASURED 2026-08-27, and it is smaller than it looks. `net.rs` (2,180 lines)
   and `direct.rs` (1,838) reach into the CLI in only ~23 places, and 15 of those
   are `ui::trace` / `ui::debug`. The full list of what must be injected:

   | dep | sites | why it is host-bound |
   |---|---|---|
   | `ui::trace` / `ui::debug` | 15 | terminal output; becomes a log hook |
   | `doctor::ip_class`, `iface_for_ip` | 4 | classifies local interfaces |
   | `settings::get_str`, `raw_membership` | 2 | user config |
   | `platform::Paths::config_path` | 1 | the signaling-DNS cache file |
   | `interact::enumerate_interfaces` | 1 | shells out to `ip` |

   So the carve is a log facade plus four small injected traits, not a rewrite.
   `Conn` is the harder half: it carries link state, adoption policy and
   presentation together, and it is what the eight event loops all manipulate,
   so it should be split as part of step 4 rather than dragged out whole here.

   DONE 2026-08-27, in two commits on purpose. First the sideways dependencies
   were cut in place, leaving both files at zero `crate::` references and
   verified live. Only then did the files move, which was by then a `git mv`
   plus three visibility promotions. Splitting it that way meant the risky
   commit landed on code already proven decoupled.

   `Conn` did NOT come with it, and still lives in `main.rs`: it carries link
   state, adoption policy and presentation together, and it is what all eight
   event loops manipulate, so it belongs with step 4.

4. **`filament-peerloop`** — one driver replacing the eight hand-written loops.
   Do this LAST: it should be assembled from the crates above, not extracted
   around them. Where the eight copies disagree, take the bug-free one, the way
   `fleet_session` took the daemon's per-peer bindings rather than the sender's
   single values.

The CLI keeps what is genuinely its own: argument parsing, the terminal UI,
config and settings, the daemon lifecycle, and the ctl socket.

## What NOT to do

Do not extract the transfer ORCHESTRATION yet, only its mechanics. `send_cmd`
interleaves establishment, the PAKE ceremony, its own event loop, offers,
chunking, resume and progress across ~1,650 lines, and it is the path with a
measured corruption history (~44% on direct-QUIC, ~88% on the DataChannel,
before the short-write fix). It needs the transport and proto crates underneath
it first, and it needs to be done against the transfer gates and the
test-record pipeline rather than as a tail-end change.

Extract mechanics, then vocabulary, then transport, then the loop. In that
order the risky step is last and lands on top of things that are already tested.

## Where things moved

The carves relocated files that other documents point at. Instructional
references (the proof gate's own comment, `proofs/README.md`, WORK-STATE) were
updated; older design docs still name the old paths and are left as the
historical record they are.

| was | is now |
|---|---|
| `cli/src/net.rs` | `crates/filament-transport/src/net.rs` |
| `cli/src/direct.rs` | `crates/filament-transport/src/direct.rs` |
| `cli/src/protocol.rs` | `crates/filament-proto/src/lib.rs` |
| `cli/src/overlay.rs` | `crates/filament-overlay/src/lib.rs` (+ host glue kept in place) |
| `cli/src/fleet_session.rs` | `crates/filament-fleet/src/session.rs` |
| `cli/src/fleet.rs` | `crates/filament-fleet/src/lib.rs` (+ host glue kept in place) |

A moved file that leaves stale pointers in a GATE's own instructions is the
instrument problem in miniature: the check still runs, but the note telling you
what to re-verify sends you somewhere that no longer exists. `proof.yml` has no
path filters, so the gate itself never stopped firing; only its comment was
wrong. That was luck rather than design, and worth knowing before adding path
filters to any workflow here.
