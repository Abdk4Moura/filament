# Startup cost and footprint

> Status: implemented (2026-09-05). Measurement record and rationale for the shipped startup/footprint work; re-measure before making new performance claims.

## Why this document exists

"It takes a while to start" was reported and could NOT be reproduced on the
development box: every local command measured 40-57ms cold. Guessing from that
position wastes the reporter's time, so the first deliverable was an instrument
rather than a fix: `experiments/startup-bench.sh` and
`experiments/footprint.sh`, both runnable on the machine that actually feels
slow.

## What startup was actually spending

`strace -c` on `filament --version`, which does nothing but print a string:

    4 clone3      227 syscalls      7.0ms of syscall time

Four threads, on a four-core box, to print a version string. `#[tokio::main]`
builds a MULTI-THREADED runtime unconditionally, spawning one worker per CPU
before `main` runs. The cost therefore scales with core count: the bigger the
machine, the slower the trivial commands feel, which is the opposite of what
anyone expects and is a good candidate for the original report.

The fix is to pick the runtime AFTER looking at the command
(`is_light_command`). Trivial, local-only verbs get a current-thread runtime;
everything else, including anything unrecognised or added later, keeps exactly
today's multi-threaded behaviour. The polarity is deliberate: a wrong answer is
a throughput question, never a correctness one, because a current-thread runtime
still runs every future and still has a blocking pool. The single API that would
panic there is `block_in_place`, and the tree contains none.

    after: 0 clone3      116 syscalls      2.0ms of syscall time

## Binary size

`size -A` said where 28.7MB lived: `.text` 21.2MB, then 3.6MB of UNWINDING
tables (`.eh_frame` + `.gcc_except_table`).

`lto = "fat"` with `codegen-units = 1` took the binary from **28.7MB to 19.5MB**
and, because better inlining also means less to relocate and page in, took
startup down with it. Release build time roughly doubled (5m20s to 10m40s),
which is paid by CI and by nobody else.

`panic = "abort"` would have removed most of those 3.6MB and was REJECTED, not
overlooked. `cli/src/tun/netstack.rs` wraps `iface.poll` in `catch_unwind`
specifically so a packet-level panic on hostile input stays contained. With
`panic = "abort"` a malformed packet from a peer would abort the process
instead: a remote denial of service traded for 12% of a binary.

## Measured, before and after

| metric | before | after |
|---|---|---|
| binary | 28.7 MB | **19.5 MB** |
| `--version`, warm | 10.5 ms | **8.4 ms** |
| minus the 4.2ms process floor | 6.3 ms | **4.2 ms** |
| threads spawned for `--version` | 4 | **0** |
| one-shot peak RSS | 10.4 MB | **9.3 MB** |
| daemon idle RSS | 25.8 MB | **22.0 MB** |
| daemon idle CPU | 0 ticks/10s | 0 ticks/10s |

## The metrics this kind of tool is judged on

Throughput is the one benchmarks report and the one users notice least. For a
tool with a daemon half, in rough order of how much they matter:

1. **Idle RSS.** A daemon holds it 24/7, and it decides whether the tool belongs
   on a small box at all.
2. **Idle CPU / wakeups.** The battery metric. A daemon that wakes constantly is
   worse than one using more RAM, and it never appears in a throughput
   benchmark. Filament is at 0 ticks per 10 idle seconds, meaning it genuinely
   waits rather than polls. This is already good and worth not regressing.
3. **Binary size.** What you ship, and the hard limit on flash-constrained
   targets.
4. **Startup latency.** Paid on every single CLI invocation.
5. **Per-peer scaling** of threads, fds and memory. Fine at one peer, decisive
   at fifty.
6. **Peak RSS under load**, which is where buffer sizing shows up.
7. **CPU per byte** moved, which is what actually limits throughput on a small
   ARM core.

## Cutting it further: what a second look found

An earlier version of this document said 19.5MB was a dependency problem that "no
profile flag closes". That was a conclusion drawn after trying two flags, and it
was wrong. `cargo bloat --crates` and `cargo tree` found three more cuts:

**A crypto library we never call: 2.6MB.** `cargo bloat` put `aws_lc_sys` at
1.3MB of `.text`, third largest crate in the binary. `main.rs` already explains
why it is there: two providers land in the tree and rustls refuses to guess, so
the code installs `ring` explicitly. But `rustls` was declared as
`features = ["ring"]` WITHOUT `default-features = false`, so rustls compiled its
default provider too, and `reqwest`'s default TLS pulled a third path into it.
Setting `default-features = false` on rustls and switching reqwest to
`rustls-no-provider` (we install the provider ourselves) removed `aws-lc-rs` and
`aws-lc-sys` from the graph entirely: **19.5MB to 16.9MB**. Verified by a real
transfer over the real signaling server, because a crypto change that merely
compiles has proved nothing.

**Cold crates optimised for size: 1.3MB.** `opt-level = "z"` costs throughput, so
it is applied per-package to crates that are not on the bulk-data path: argument
parsing, the HTTPS control plane, and WebRTC session setup. `ring`, `quinn`,
`tokio`, `smoltcp` and filament's own crates stay at full optimisation.
**16.9MB to 15.6MB**, and throughput was re-measured on the two-machine rig
rather than assumed: 4 runs each of a 30MB transfer, median 18.1 MB/s before and
18.6 MB/s after, with run-to-run variance far exceeding the difference.

**Duplicate dependency versions.** 30 crate names appear at more than one
version. Most are small, but `reqwest` is there twice (0.12 via `rust_socketio`,
0.13 ours). `hyper`, `h2`, `rustls` and `ring` unified to single versions once
the TLS features were fixed, which removed most of the real cost; the remaining
reqwest duplication is roughly 200KB and would need `rust_socketio` to move.

## Totals

| metric | start | now |
|---|---|---|
| binary | 28.7 MB | **15.6 MB** (-46%) |
| `--version` warm | 10.5 ms | **8.5 ms** |
| threads for `--version` | 4 | **0** |
| one-shot peak RSS | 10.4 MB | **8.8 MB** |
| daemon idle RSS | 25.8 MB | **21.5 MB** |
| daemon idle CPU | 0 ticks/10s | 0 ticks/10s |


## Calibration: is 15.6MB actually big?

The earlier comparison in this document was against tmux (1.1MB) and it was
MISLEADING, in a way worth spelling out because it is a common mistake. tmux is
a dynamically-linked C binary: the 1.1MB is the part that is not libc, ncurses,
libssl and so on. Its real closure, binary plus the shared libraries it loads,
is 8.1MB. Measured the same way on the same machine:

| tool | binary | + its shared libs |
|---|---|---|
| curl | 0.3 MB | **19.4 MB** |
| tcpdump | 1.2 MB | 13.3 MB |
| ssh | 0.8 MB | 10.4 MB |
| nginx | 1.3 MB | 10.1 MB |
| openssl | 1.0 MB | 8.9 MB |
| tmux | 1.1 MB | 8.1 MB |

So curl, the canonical "small" tool, actually pulls in MORE than filament does.

Against tools in filament's own class, which carry their own TLS, crypto and
protocol stacks rather than borrowing the system's:

| tool | size | what it does |
|---|---|---|
| node | 118.9 MB | JS runtime |
| dockerd | 99.0 MB | container daemon |
| containerd | 45.9 MB | container runtime |
| docker (CLI) | 43.5 MB | client only |
| **tailscaled** | **40.9 MB** | mesh VPN daemon |
| cc1 (GCC's actual compiler) | 32.6 MB | C compiler backend |
| **tailscale (CLI)** | **31.6 MB** | mesh VPN client |
| rustc / cargo | 19.9 MB | compiler / build tool |
| **filament** | **15.6 MB** | mesh + transfer + mount + shell |
| croc | 14.9 MB | file transfer only |

filament is **half the size of the Tailscale CLI and 2.6x smaller than
tailscaled**, while doing more than either: the mesh, plus file transfer, plus a
FUSE mount, plus a web shell. It is within a megabyte of croc, which only
transfers files. `gcc` is a 1MB driver that execs `cc1`, and `cc1` is 32.6MB, so
"as big as a C compiler" would in fact be twice filament's size.

The conclusion is not that size stopped mattering. It is that the target should
be croc's ~15MB rather than tmux's apparent 1.1MB, and filament is already there.

## Ledger C16 closed: rust_socketio replaced

filament used to link the system `libssl`/`libcrypto` because `rust_engineio`
(under `rust_socketio`) depends on `native-tls` UNCONDITIONALLY, not behind a
feature. That was recorded as ledger C16 and treated as unfixable without
forking upstream.

It did not need a fork, because filament used almost none of that crate. The
client already forced `TransportType::Websocket` (polling behind Cloudflare
caused a documented reconnect storm) with `reconnect(false)`, every handler only
pulled the first JSON value out of a payload and forwarded it to one channel,
and the only methods called were `emit`, `emit_with_ack`, `disconnect` and
`clone`. What was actually needed was a websocket, Engine.IO's framing digits,
and Socket.IO's `42["name",data]` and `43<id>[...]`.

`crates/filament-signal` is that, on rustls, in about 300 lines with 7 protocol
tests. Scope is deliberately narrow and anything outside it is an error rather
than a silent no-op: websocket only, no polling upgrade, no binary attachments,
no library-level reconnect (filament's outer loop must re-run join/subscribe/sync,
which a silent reconnect would skip).

Acks were the part that mattered. Two callers depend on them and both fixed real
bugs: the liveness heartbeat, whose ack is the only proof a quiet socket is alive
(without it the watchdog false-reconnects idle links), and the subscribe roster,
whose ack replaced a lossy one-shot push that stalled ~40% of establishment
attempts. A timeout returns `Ok(None)` rather than an error, because not hearing
back is ordinary and the callers already retry.

What it bought:

| | before | after |
|---|---|---|
| linked libraries | libc, libssl, libcrypto, libgcc, libm | **libc, libgcc, libm** |
| closure (binary + libs) | 24.7 MB | **18.4 MB** |
| binary | 15.6 MB | **15.1 MB** |
| crates in the tree | 503 | **483** |
| `reqwest` versions | 0.12 and 0.13 | **0.13 only** |
| `native-tls` / `openssl` | present | **absent** |

Verified against the real signaling server, not just compiled: a 3MB transfer to
a remote peer completed and verified (which exercises connect, the subscribe ack
roster, peer discovery and the data path), and a daemon held a connection for
200s with zero `SignalingDown` and zero reconnects. The silence watchdog fires at
30s, so surviving 200s is direct evidence the heartbeat acks are arriving.

## Where the remaining weight is, honestly

15.6MB against tmux's 1.1MB is still an order of magnitude, and no
profile flag closes that. The weight is dependencies: 509 crates, including
`webrtc`, `quinn`, `smoltcp`, `reqwest`, `portable-pty`, `zip`, `tar`,
`qrcode` and `clap_mangen`, plus `tokio` with `features = ["full"]`.

Getting genuinely small is therefore a FEATURE-GATING problem, not an
optimisation problem: a `--no-default-features` build that drops the web shell
(portable-pty), FUSE mount (fuser), archive support (zip/tar), QR rendering and
man-page generation, and ideally offers a relay-free build without `webrtc`.
That is a real piece of work with a real payoff and it has not been done. It
should be measured with `experiments/footprint.sh` before and after, not
estimated.

## Where startup stands, and what did not help

After the runtime and size work, `--version` measures 6.7ms against a 3.7ms
process floor on this box: about **3ms is filament**. The profile says there is
not much left to take:

- 94 syscalls, 1.55ms of syscall time, of which `execve` alone is 0.59ms. That
  is the kernel loading the image and is bounded by binary size, which is why
  the size work moved startup at all.
- The dynamic loader costs 239k cycles total, ~0.1ms, with 322 relocations.
  Static linking would target that 0.1ms and is not worth the musl trade.

**A hypothesis that measured zero.** Installing the rustls crypto provider runs
on every invocation, including `--version`, which never opens a socket. Skipping
it for local-only commands looked like obvious waste. Measured: 6.7ms with and
without, no difference. The change was reverted rather than kept, because it put
a branch in front of crypto initialisation and bought nothing. Recorded here so
nobody re-derives it and assumes it works.

What remains is genuinely small and would need evidence from a machine where
startup is actually slow, since none of the profiling here reproduces the
original report. `experiments/startup-bench.sh` exists for exactly that.

## WireGuard vs the QUIC-datagram plane: measured

`experiments/wireguard-throughput.sh` pushes a TCP stream over the OVERLAY
(not filament's file-transfer path, which has its own framing and would measure
that instead) between do-vm and a KVM VPS, and reports MB/s.

| plane | runs | median | spread |
|---|---|---|---|
| QUIC datagrams | 13.82, 9.15, 7.18, 10.47 | **9.81 MB/s** | 7.18-13.82 (68% of median) |
| WireGuard | 7.24, 9.23, 7.91, 7.66 | **7.79 MB/s** | 7.24-9.23 (26% of median) |

An earlier QUIC sample the same evening was 4.89-15.38 MB/s, median 10.80.

### Reading this honestly

WireGuard measures about **20% slower** here, and that is INSIDE the noise, not a
result. The QUIC arm's own spread is 68% of its median and it ranged 4.89 to
15.38 MB/s across the session: a 20% gap between two samples drawn from that is
not a difference anyone should act on. The only claim these numbers support is
that **WireGuard is in the same class**, not that it is faster or slower.

Two things do stand out and are worth keeping:

- **WireGuard is markedly more CONSISTENT** (26% spread against 68%). That is
  what one would expect from moving crypto into the kernel and off a
  single-threaded userspace loop, but with four runs it is a hint, not a finding.
- **The bottleneck is almost certainly the internet path, not either plane.**
  Both sit near 8-11 MB/s on a link whose file-transfer throughput has been
  measured at 18-19 MB/s elsewhere in the session, so this benchmark is probably
  measuring the sink, the single TCP stream, or the path rather than the data
  plane.

### What would actually settle it

A same-host measurement between two namespaces, where the wire is not the
bottleneck, with enough runs to separate the medians. Until that exists,
`wireguard` stays OPT-IN: there is no evidence it is faster, and shipping a data
plane change on a hint would be the opposite of how the rest of this work was
done.
