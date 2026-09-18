# Agent-grade output audit

Can a script or an agent drive every filament verb without reading prose? Today,
no. This is the evidence, verb by verb, and the two conventions that would fix it.

Read-only audit of `origin/main` (3f51592). Nothing was built or run; every claim
is a citation. What I could not settle from the source is marked **unverified**.

## The three findings that matter most

1. **`--json` is advertised for every command and reaches ten.**
   `cli/src/cli_def.rs:123` says "JSON output for every command (structured,
   parseable)". `cli/src/dispatch.rs:406-424` refuses it outside
   `Init | Add | Join | Id | Status | Set | Reach | Doctor | Addr | Devices{action:None}`.
   Three of those ten accept the flag and ignore it: `add`/`join` over the code
   transport reach `pair_cmd`, which has no json parameter
   (`dispatch.rs:978`, `:1019`; `pair_cmd.rs:106-114`), and `set <key> <value> --json`
   writes human lines with `eprintln!` (`settings.rs:950-963`). And no verb emits JSON
   on a failure: `doctor --json` propagates with `?` at `doctor.rs:62` and prints prose
   instead, so the one mode that promised parseability abandons it exactly when a
   caller needs the reason.

2. **Real failures exit 0.** `expose` returns success whether the port is serving or
   nothing is listening: the "applied to the running daemon" branch (`expose.rs:147-151`)
   and the two "saved; takes effect later" branches (`:153-163`) are indistinguishable to
   a caller. `receive` declines every offer on a non-TTY and exits 0
   (`recv_cmd.rs:5545-5557`, `:6504-6512`) and refuses a corrupt file with `continue`
   (`:5854-5865`, `:6009-6020`). `requests approve|deny` on a missing id or a dead daemon
   says so and returns `Ok(())` (`status_cmd.rs:258-262,278-282`). `logs` returns `Ok(())`
   after a *failed* journal read (`up_logs.rs:359-369`). `down` reports "stopped" without
   checking that `kill` took (`main.rs:1439-1443`). `set --reset` aborted at the prompt
   exits 0 (`settings.rs:1019-1022`).

3. **`shell` throws away the remote exit status, and `exec`'s collides with filament's
   own.** `PtyOutcome::Exited` is a unit variant carrying no code (`l2.rs:2582-2585`,
   produced at `:2894`), so `dispatch.rs:1253` → `l2.rs:3086` returns `Ok(())` and a
   remote `exit 3` reads as local success; `shell --ssh` is correct (`l2.rs:4769,4772`).
   `exec` does propagate (`dispatch.rs:1315-1318`; `exec_send.rs:264,339-342`), but
   `fn main() -> Result<()>` (`main.rs:1671-1682`) leans on Rust's default `Termination`,
   so *every* `bail!` is also exit 1: unknown device, ceiling denial, connect timeout and
   a remote `false` are one number (`exec_send.rs:100-110,171-194,226-288`;
   `dispatch.rs:1284,1287-1294`).

## 1. The inventory

`json?` = does `--json` produce structured JSON. `codes` = distinct exit codes
reachable. `non-int` = no TTY or `--no-interactive`. `ready` = a line an agent can
wait on. Every `ui::` helper writes to **stderr** (`ui.rs:279-289`) and `ui::say` is
suppressed by `-q` (`:294-298`), so "ready via `ui::say`" means "invisible under `-q`".

| verb | json? | exit codes | stdout / stderr | non-interactive | ready line | evidence | sev |
|---|---|---|---|---|---|---|---|
| `init` | yes, success only | 0 / 1 | JSON on stdout | ok; refuses `--json --background` | n/a | `identity_flow.rs:241-243,352-363` | low |
| `add --out` | yes, success only | 0 / 1 | JSON on stdout | ok | n/a | `add_for.rs:332-340` | low |
| `add` (code) | **accepted, ignored** | 0 / 1 / 2 | prose | exits 2, real message | n/a | `dispatch.rs:978`; `pair_cmd.rs:106-118`; `fleet_ui/pair_ui.rs:135` | **high** |
| `join <code>` | **accepted, ignored** | 0 / 1 / 2 | prose | as above | n/a | `dispatch.rs:1019`; `pair_cmd.rs:115-119` | **high** |
| `join --invite-file` | yes, success only | 0 / 1 | JSON on stdout | ok | n/a | `identity_flow.rs:498`; `enrollment.rs:372-383` | low |
| `id` | yes | 0 / 1 | JSON on stdout; **prose also on stdout** | n/a | n/a | `dispatch.rs:656-765` | med |
| `send` | refused | 0 / 1 / 130 | nothing on stdout | fails fast, clear | n/a | `dispatch.rs:421`; `send_cmd.rs:101-105,2055-2061,1847` | **high** |
| `receive` | refused | 0 / 1 / 130 | stdout only for `-o -` payload | auto-declines, **exit 0** | `ui::say` "listening," | `recv_cmd.rs:400-407,5545-5557,5854-5865,6504-6512` | **high** |
| `exec` | refused | 0 / **1 for every local failure** / remote status | correct: remote out→out, err→err | fails fast, clear | n/a (one-shot) | `exec_send.rs:99-110,171-194,264,339-342`; `dispatch.rs:1284-1318` | **high** |
| `shell` | refused | 0 / 1; **remote status dropped** | PTY payload on stdout | fails fast, clear | none (implicit first bytes) | `l2.rs:2582-2585,2894,3086,3122,3132,3190,3219` | **high** |
| `shell --ssh` | refused | ssh's own code | PTY | ok | none | `l2.rs:4769,4772,4825` | low |
| `reach` | yes | **0 always** | **human prose on stdout** | ok | n/a | `ping.rs:26-30,188-204`; `dispatch.rs:1326` | **high** |
| `doctor` | yes; **not on the error path** | **0 always** | JSON on stdout | ok | n/a | `doctor.rs:38-96,293-310` | **high** |
| `forward` | refused | 0 / 1 for all four failure classes | clean stdout; counters via `ui::status` vanish on a pipe | ok | **four** different `ui::say` strings | `l2.rs:3444,3452-3489,3491-3546,3552-3608`; `ui.rs:373-375` | **high** |
| `forward --socks` | refused | 0 / 1 | clean stdout | ok | `ui::say` "SOCKS5 proxy on …" | `l2.rs:3617,3626-3678`; `dispatch.rs:1389` | med |
| `forward --stdio` | refused | 0 / 1 (`exit(1)` at `l2.rs:2489`) | **clean; payload only** | ok | none, by design | `l2.rs:2440-2545` | low |
| `expose` | refused | **0 whether serving or not** | **nothing on stdout, incl. `--list`** | `--off` needs `-y` | n/a (not long-running) | `expose.rs:82-138,141-164,231-234` | **high** |
| `mount` | refused | 0 / 1; `--check` exits 1 when unhealthy | **help, `--list`, `--check` prose on stdout** | `--off` needs `-y` | two `ui::say` lines, before the FUSE session | `mount_cmd.rs:307-349,371-375`; `mount.rs:291,376,485-499,545-558,562,785-808` | **high** |
| `up` | refused | 0 / 1 / 130 | clean stdout | ok | `ui::say` only; `sd_notify` READY=1 | `up_logs.rs:25-320`; `recv_cmd.rs:371-378,400-407,939-953`; `sdnotify.rs:46` | **high** |
| `down` | refused | **0 always** | prose via `ui::` | n/a | n/a | `main.rs:1430-1451` | med |
| `logs` | refused | **0 always**, incl. Ctrl-C and a failed journal read | **payload on stderr**, except the journalctl path where it is stdout | ok | n/a | `up_logs.rs:339-370,374-378,391,440-441,466` | **high** |
| `status` | yes | **0 always** | JSON on stdout | n/a | n/a | `status_cmd.rs:93-115` | med |
| `devices` | yes, **bare array, no envelope** | 0 / 1 | JSON on stdout | n/a | n/a | `dispatch.rs:1029-1047` | med |
| `devices forget/rename/revoke/restore` | refused | 0 / 1 | **prose on stdout** | `revoke` needs `-y` | n/a | `dispatch.rs:1097-1148` | med |
| `requests list` | refused | 0 / 1 | prose on stderr only | n/a | n/a | `status_cmd.rs:213-230` | **high** |
| `requests approve/deny` | refused | **0 on not-found** | prose | ok | n/a | `status_cmd.rs:238-282` | **high** |
| `grant` | refused | 0 / 1 | **prose on stdout** | n/a | n/a | `dispatch.rs:1472,1703-1710` | med |
| `revoke` | refused | 0 / 1 | prose on stdout, warnings via `eprintln!` | needs `-y` | n/a | `dispatch.rs:1758,1824-1862` | med |
| `ephemeral enroll` | **refused, and hardcoded off** | 0 / 1 | prose | ok | n/a | `main.rs:1358` passes `false`; `enrollment.rs:169-187` | med |
| `addr` | yes | 0 / 1 | JSON on stdout; **prose also on stdout** | n/a | n/a | `dispatch.rs:546-640` | med |
| `reset` | refused | 0 / 1 | mixed | refuses without `-y` | n/a | `mount_cmd.rs:28-41` | low |
| `set` (readout) | yes | 0 / 1 | JSON, else TSV, on stdout | TSV on a pipe: good | n/a | `settings.rs:1177-1215` | low |
| `set k v` | **accepted, ignored** | 0 / 1 | `eprintln!` prose | ok | n/a | `settings.rs:936-963` | **high** |
| `set --reset` | no | **0 on abort** | `eprintln!` prose | refuses without `--yes` | n/a | `settings.rs:987-1032` | med |
| `depart`/`netcat`/`backup`/`config`/`update`/`completions`/`man` | refused (hidden) | 0 / 1; `backup.rs:147` passes rsync's code through | mixed | varies | n/a | `cli_def.rs:298,454,460,470,475,510,650` | low |

What the table alone hides:

- **`filament shell` has no help text.** The doc comments at `cli_def.rs:671-685`
  ("Open a shell on a device…") sit immediately above `Exec {` at `:686`, so clap
  attaches all of them to `exec`; `Shell {` at `:705` gets nothing. `filament --help`
  lists `shell` blank and `filament exec --help` describes a shell. Discovery is how an
  agent learns a surface.
- **`filament get` and `filament unset` do not exist.** `settings::run_get`
  (`settings.rs:786-830`) has no caller outside its module; the only arm is the hidden
  `Set` (`cli_def.rs:394-434`). `docs/design-command-surface.md:61-63` still promises them.
- **`forward --socks` silently discards its positional.** `dispatch.rs:1371-1379`
  parses `<device>:<port>`, then `:1389` does not pass it to `proxy_cmd`.
- **`logs -f` mutates host network state.** Its SIGINT arm runs
  `subnet_forward::cleanup()` and `wg::teardown` (`up_logs.rs:428,434`) from what is
  otherwise a read-only verb.
- **`UiCapability::confirm`'s pipe branch is dead.** `interactive` already requires
  `stdin().is_terminal()` (`main.rs:458`), so the line-reading `else` at `:496-505`
  cannot run and the comment at `:476` ("`echo y | filament ...` is unchanged") is false:
  a piped `y` hits `:514` and fails. Fail-closed is right; the dead branch is not.
- **Not reproduced:** the reported raw `os error 98` from `forward`. `l2.rs:3475-3477`
  catches `AddrInUse` and emits `port_in_use_msg` (`:3245-3251`) with no io text. Raw io
  errors do leak from `expose.rs:231-234` and the non-`AddrInUse` bind arms at
  `l2.rs:3485-3489,3629-3633,3665-3668`. Whether the note predates `port_in_use_msg` is
  **unverified**.

## 2. Long-running verbs

| verb | ready | stop | notes |
|---|---|---|---|
| `up` | `ui::say` banner (`recv_cmd.rs:371-378` or `:400-407`) fires *before* serving; the real edge is `sdnotify::ready()` at `:939`, systemd-only | Ctrl-C/SIGTERM → 130 (`recv_cmd.rs:477-496`, `shutdown.rs:54-61`); `filament down` | a non-systemd agent must poll `{config}/up.pid` (`file_io.rs:17-30`) and `control.sock` (`ctl.rs:32-34,100`) |
| `forward` | four distinct strings: `"forwarding"` (`l2.rs:3491`), `"ready - "` (`:3517`), `"listening on"` (`:3522`), `"ready, listening on"` (`:3543`) | **no SIGINT handler** (`:3552-3608`); default signal disposition | only `:3491` is guaranteed, and it precedes any link |
| `forward --socks` | `l2.rs:3635-3637`, plus `:3670-3672` for HTTP CONNECT | no handler | per-connection errors are `ui::debug`, so a failing proxy is silent |
| `forward --stdio` | none, deliberately | stdin EOF / peer FIN (`l2.rs:2518-2545`) | the one verb with provably clean stdout |
| `expose` | not long-running: it writes a file and returns (`expose.rs:32-54`) | `expose --off <port>` (`dispatch.rs:1408-1415`); off-when-not-exposed also exits 0 (`expose.rs:118`) | readiness belongs to `up`; see finding 2 |
| `mount` | `mount_cmd.rs:337-349`, emitted before the FUSE session is spawned at `:353-359` | Ctrl-C handled → **exit 0** (`:371-375`); `mount --off <path>` | small race between the ready line and serving |
| `logs -f` | n/a | Ctrl-C → "detached", **exit 0** (`up_logs.rs:438-443`) | source is `daemon.log` when present, else `diag.jsonl` (`:374-378`), so the format is unknowable to the caller |

## 3. Proposed exit-code convention

One enum, mapped onto sites that already distinguish the case in prose.

| code | name | means | existing site |
|---|---|---|---|
| 0 | `Ok` | the verb did what it said | n/a |
| 2 | `Usage` | bad arguments, missing value, exclusive flags | already 2: `dispatch.rs:233,258,275,289`; `interact.rs:86,100`; `pair_ui.rs:135` |
| 3 | `UnknownDevice` | not paired, no such petname, roster-only sibling | `identity_state.rs:194-215`; `device_caps.rs:211-215`; `dispatch.rs:553,1077,1114,1135` |
| 4 | `Denied` | capability, invitation ceiling, consent or revocation refused it | `dispatch.rs:1219-1226,1289-1296,1542-1550,1747-1756`; `l2.rs:3090-3122`; `exec_send.rs:171-194`; `recv_cmd.rs:5510-5517` |
| 5 | `Unreachable` | no path to the peer, or a timeout | `exec_send.rs:100-110,189-193`; `l2.rs:3219,3536-3542`; `ping.rs:200`; `doctor.rs:62` |
| 6 | `RemoteFailure` | the peer answered and the session failed | `exec_send.rs:226-288,339-342`; `recv_cmd.rs:6427-6431`; `mount_cmd.rs:315-324` |
| 7 | `Partial` | some work landed; verify failed; a decline left it incomplete | `send_cmd.rs:2055-2061`; `recv_cmd.rs:5854-5865`; `expose.rs:153-163` |
| 130 | `Interrupted` | SIGINT | already `recv_cmd.rs:6339`, `send_cmd.rs:1847`, `shutdown.rs:60` |

`1` remains the catch-all for anything not yet classified, so the change is additive and
no script that only tests `!= 0` breaks. Mechanically: an `enum ExitKind` with
`fn code(&self) -> u8`, a `FilamentError { kind, source }` wrapper, and
`main.rs:1671-1682` becoming `fn main() -> ExitCode`. The sites above already know their
kind; each gains one `.kind(...)` and nothing else.

`exec` keeps passing the remote status through (the ssh precedent; `CONTRACT.md:320-327`
already fixes the wire semantics at 128+signal). The collision is resolved by `--json`:
under it `exec` exits 0 whenever the command was *delivered* and reports the remote
status in `data.status`. `shell` should adopt the same propagation `shell --ssh`
already has.

## 4. Proposed JSON envelope

```json
{"ok": true,  "verb": "devices", "data": {"devices": [ … ]}}
{"ok": false, "verb": "exec", "error": {"code": "unknown_device", "exit": 3,
                                        "message": "no device named 'nosuchdev'"}}
```

Exactly one JSON document on stdout, never interleaved with anything else.
`error.code` is a stable snake_case token from the `ExitKind` names plus a per-verb
refinement; `error.exit` repeats the process code. `data` preserves today's shapes
verbatim one level down: `devices` keeps its array (`dispatch.rs:1037-1044`) as
`data.devices`, `status` keeps `{running,pid,devices,exposed,recent}`
(`status_cmd.rs:106-112`) as `data`, `doctor` keeps `kind: "filament-doctor-probe"`
(`doctor.rs:293-310`) as `data`. No existing consumer re-learns a field.

Two rules that keep it honest:

- **The error path emits the envelope too.** Today `doctor --json` propagates at
  `doctor.rs:62` and prints prose; `reach --json` prints `{"ok":false,…}` and exits 0
  (`ping.rs:200-204`). Same defect from opposite ends.
- **`ok` describes the outcome, not the invocation.** `reach --json` on a dead peer is
  `ok:false`, exit 5. `status --json` with the daemon down is `ok:true`,
  `data.running:false`, exit 0: status reports, it does not attempt.

## 5. Conflicts with the existing contract

- `docs/ui/OUTPUT.md:91` ("stdout is for machines") and
  `docs/design-command-surface.md:140` ("stdout stays script-clean") are violated by
  `reach` (`ping.rs:30`), `addr`, `id`, `grant`, `revoke`, the `devices` mutations, and
  most of all `mount.rs`, which prints its 24-line help block (`:785-808`), `--check`
  (`:485-499`) and `--list` (`:545-558`) to stdout. `mount --list` is also tty-branched
  at `:545`, so a pipe gets an undocumented space-separated form nothing specifies.
- `docs/ui/OUTPUT.md:92-93` ("stderr … always through `ui::`. Never `eprintln!`") is
  violated wholesale by `settings.rs:940-1031`, `up_logs.rs:105,297,391,466`,
  `mount_cmd.rs:253-268` and `dispatch.rs:1695,1824,1838,1845,1861`.
- The ratchet at `cli/tests/surface_output.rs:24-59` counts `println!` and `eprintln!`
  in one number, so adding a legitimate `--json` emitter on stdout costs exactly what
  adding human prose on stderr costs. The two macros should be budgeted separately:
  `eprintln!` monotone down, `println!` free to grow for `--json` work.
- `docs/ui/OUTPUT.md` says 338 grandfathered sites; the budget sums to 328, and
  `surface_output.rs:26-27` says so itself. A stale number in the doc enforcing it. The
  same doc has no section on exit codes or JSON at all: it governs what is printed and
  is silent on what is returned, which is how finding 2 went unnoticed.
- `cli_def.rs:380` describes `logs` as "the daemon's diagnostic timeline (diag.jsonl)";
  `up_logs.rs:374-378` prefers `daemon.log`, which is human console text with ANSI.

## 6. Tickets

One PR each. None touches `dispatch.rs` beyond its own match arm, except 1-3, the shared
substrate, which land first. *Accept* is the gate; `jq -e` means the run must also succeed.

1. **Envelope + emitter.** `ui::json_ok(verb, data)` / `ui::json_err(verb, kind, msg)`
   writing §4 to stdout; no verb changes yet. *Accept:* unit tests assert both shapes.
2. **`ExitKind` and `main -> ExitCode`.** §3 enum, `FilamentError`, default arm 1; no call
   site reclassified yet. *Accept:* `filament nosuchverb; echo $?` still prints 2, and a
   classified error in a test binary yields its code.
3. **`--json` honesty gate.** Under `--json`, route the `dispatch.rs:421` refusal and every
   later `bail!` through `ui::json_err`, so `--json` never emits prose.
   *Accept:* `filament exec nosuchdev --json -- true | jq -e '.ok == false'`, and all of
   stdout parses as JSON.
4. **`exec`.** `--json` with `data.status`; `dispatch.rs:1284` → 3; `:1287-1294` and
   `exec_send.rs:171-194` → 4; `:100-110,189-193` → 5; `:226-288,339-342` → 6; bare
   pass-through unchanged without `--json`.
   *Accept:* `filament exec nosuchdev -- true; echo $?` prints 3;
   `filament exec laptop --json -- sh -c 'exit 7' | jq .data.status` prints 7 with `$?` 0.
5. **`shell`.** Carry the remote status on `PtyOutcome::Exited` (`l2.rs:2582-2585,2894`) and
   propagate at `:3086` as `shell --ssh` already does (`:4769`); `:3122,3132` → 4,
   `:3190,3219` → 5; restore the terminal before each `exit` (they skip `Drop`).
   *Accept:* a remote `exit 3` gives local 3; a refused shell exits 4.
6. **`devices`.** Array becomes `data.devices`; `forget/rename/revoke/restore/vouch` get a
   `--json` result and move their prose from `println!` to `ui::say`; unknown name → 3.
   *Accept:* `filament devices --json | jq -e .ok`; `filament devices forget nope; echo $?`
   prints 3.
7. **`status` + `addr` + `id`.** Envelope; human renderings off stdout onto `ui::say`.
   *Accept:* `filament status --json | jq -e .ok`; human-mode `addr` puts nothing but the
   address on stdout.
8. **`reach`.** One schema for the warm and cold paths (`ping.rs:189-201`); envelope on the
   error path; exit 5 when unreachable; `ping.rs:30` → `ui::say`.
   *Accept:* `filament reach nosuchdev; echo $?` prints 3;
   `filament reach <offline> --json | jq -e '.ok == false'` with `$?` 5.
9. **`doctor`.** Emit the envelope instead of propagating at `doctor.rs:62`; exit 5 when the
   probe did not establish; one `kind` per mode, all under `data`.
   *Accept:* `filament doctor <offline> --json | jq -e .error.code` with valid JSON on
   stdout and `$?` 5.
10. **`send`.** `--json`: one JSONL record per file on stdout plus a final envelope; keep the
    CR bar for TTYs (`ui.rs:449`); declined or partial → 7, today 1 (`send_cmd.rs:2060`).
    *Accept:* `filament send f --to dev --json | jq -s '.[-1].ok'`; a declined transfer exits 7.
11. **`receive`.** A ready record on stdout under `--json`; exit 7 when every offer was
    declined (`recv_cmd.rs:5545-5557`) or a file failed verification (`:5854-5865`);
    unknown `--to` → 3. *Accept:* `filament receive --json` prints
    `{"ok":true,"verb":"receive","data":{"state":"listening",…}}` within 2s; a non-TTY run
    that declines everything exits 7.
12. **`forward`.** Collapse the four ready strings (`l2.rs:3491,3517,3522,3543`) into one
    shape, on stdout under `--json` and via `ui::critical` otherwise so `-q` keeps it; add a
    SIGINT arm to the accept loop (`:3552-3608`) exiting 130; `:3462-3470` → 3,
    `:3475-3489` and `:3536-3542` → 5. *Accept:* `filament forward dev:5432 --json` emits
    the ready envelope before it blocks; a second one on the same port exits 5 with no
    "os error" in the message.
13. **`expose`.** Distinguish the three `notify_daemon` outcomes (`expose.rs:147-163`):
    serving → 0, saved-but-not-serving → 7 with the reason; `--list` and the result under
    `--json` (`Binding` at `:24-30` is already `Serialize`); wrap the raw io error at `:231-234`.
    *Accept:* `filament expose 8080 --json | jq -e .data.live`; exposing with no L3 overlay
    exits 7; `filament expose --list --json | jq length`.
14. **`mount`.** Move the help block (`mount.rs:785-808`), `--check` (`:485-499`) and
    `--list` (`:545-558`) off stdout, replacing `--list`'s tty branch with `--json`; keep
    `--check`'s nonzero but reclassify to 6; `mount_cmd.rs:315-324` → 6, `:371-375` → 130.
    *Accept:* `filament mount --list --json | jq -e .ok`; `filament mount --help` puts
    nothing on stdout.
15. **`up`.** A ready record on stdout at the same point as `sdnotify::ready()`
    (`recv_cmd.rs:939`) rather than the earlier banner at `:371-378`, so a supervisor
    without systemd can wait too. *Accept:* `filament up --json` prints one ready envelope
    and nothing else on stdout.
16. **`logs`.** Payload to stdout (`up_logs.rs:391,466`), matching the journalctl path;
    `--json` forces the `diag.jsonl` source so the format is knowable; nonzero when the
    journal fallback fails (`:359-369`); Ctrl-C → 130; drop the network teardown at
    `:428,434` from a read-only verb. *Accept:* `filament logs --tail 5 | wc -l` prints 5;
    `filament logs --json` emits one JSON object per line.
17. **`requests`.** `--json` for list/approve/deny; unknown id → 3 and no daemon → 5
    (`status_cmd.rs:258-262,278-282`); fill the silent branch at `:240-257`.
    *Accept:* `filament requests --json | jq -e .ok`; `filament requests deny 999; echo $?`
    prints 3.
18. **`grant` / `revoke`.** `--json`; prose from `println!` to `ui::say`; ceiling refusal → 4;
    `eprintln!` at `dispatch.rs:1824,1838,1845,1861` → `ui::`.
    *Accept:* `filament grant dev shell --json | jq -e .ok`; a grant outside the ceiling
    exits 4.
19. **`set`.** Honour `--json` on the write path (`settings.rs:950-963`) and on `--reset`;
    `eprintln!` → `ui::`; an aborted reset exits 2, not 0 (`:1019-1022`).
    *Accept:* `filament set relay never --json | jq -e .ok`;
    `printf 'n\n' | filament set --reset; echo $?` prints 2.
20. **`add` / `join` code transport.** Thread `UiCapability` into `pair_cmd`
    (`pair_cmd.rs:106`) and emit the envelope, or drop them from the allowlist at
    `dispatch.rs:410-411` until it does; dropping is the smaller PR and the honest one.
    *Accept:* `filament join <code> --json` either emits an envelope or exits 2 saying
    `--json` is not implemented for the code transport. It must not print prose.
21. **`ephemeral enroll`.** Pass the real flag at `main.rs:1358` instead of `false` and add
    the verb to the `dispatch.rs:407-419` allowlist.
    *Accept:* `filament ephemeral enroll --auth-key-file k --json | jq -e .ok`.
22. **`down`.** Confirm the daemon stopped before claiming it (`main.rs:1439-1443` ignores
    `kill`'s status); `--json`; exit 5 if it is still alive after the stop.
    *Accept:* `filament down --json | jq -e .ok`; stopping a wedged daemon exits 5.
23. **Docs and ratchet.** Move `shell`'s doc comments off `exec` (`cli_def.rs:671-685`);
    correct the `--json` help (`:123`) and the `logs` help (`:380`); split the ratchet budget
    into `println!` and `eprintln!` columns; add exit-code and JSON sections to
    `docs/ui/OUTPUT.md` and fix its 338; delete the dead `confirm` branch (`main.rs:496-505`).
    *Accept:* `filament shell --help` describes a shell; `surface_output.rs` reports two
    numbers per file.

## 7. Do first

The surfaces an agent touches on nearly every task, in payoff order.

1. **Ticket 4, `exec`**. The most-used verb for an agent and the only one whose exit code
   is already load-bearing; it is where a remote `1` colliding with a filament `1`
   actively produces wrong conclusions.
2. **Tickets 6 and 7, `devices` / `status` / `addr`**. Discovery: everything starts by
   asking what exists and whether the daemon is up. They already emit JSON, so this is
   the cheapest honest envelope in the tree.
3. **Ticket 11, `receive`**. The exit-0-on-total-failure case. An agent that ships a file
   and checks `$?` is told it worked when nothing was written.
4. **Ticket 10, `send`**. The other half of that loop, and the only verb with real
   progress data a script cannot see at all.
5. **Ticket 12, `forward`**. No stable ready line means every agent sleeps an arbitrary
   number of seconds and hopes.

Tickets 1-3 are the substrate all five need, so they land first and are small. Ticket 5
(`shell` dropping the remote status) is outside this five only because agents should be
reaching for `exec`; it is the worst single defect in the audit.
