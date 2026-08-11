# Testing the flows a person actually runs

One source of truth for the user-flow test work. Three owners, disjoint paths,
one rule.

## The rule

**A test asserts an invariant, not an exit code.** `filament devices forget phone`
returning 0 proves nothing. The scenario that earns its runtime is the one that
also checks another device's granted `shell` cap survived the forget, because
that is the bug that happened.

Two corollaries, both from bugs we shipped.

**Do not seed state you could produce.** Six rig scenarios write `devices.json`
by hand. That asserts we know the shape `add` produces, and between 0.8.2 and
0.8.4 that shape gained an issuer fingerprint, packed capability fields and an
expiry. Every seeded scenario passed across all of it without once running the
code that writes the store. `seed_store` is now reserved for states no ceremony
can legitimately produce: revoked, expired, corrupt. Everything else pairs for
real via `pair_two` in `rig/lib.sh`.

**A check that cannot distinguish the thing from its neighbour will confidently
return the neighbour.** This has cost us four role-election bugs, a crates.io
lane misdiagnosis, and a systemd guard that matched a user unit and a system
unit by the same substring. When a test looks something up, make it prove it
found the right one, and write the negative case where a neighbour exists.

## Current surface, as of 0.8.6

Verbs the rig still calls that no longer exist:

| rig calls | current |
|---|---|
| `pair` | `add` mints a code, `add <code>` claims it |
| `pair` (bounded) | `add --for <device\|person>`, other side runs `join` |
| `recv` | `receive` |
| `ssh` | `shell <device>`, `--ssh` for real ssh over the channel |
| `introduce` | **removed.** Not renamed. Delete the scenario. |

`add` takes `--name`, `--word`, `--for`, `-y`. `receive` takes `--dir`, `-y`.
`shell` takes `[PEER] [ARGS]...` and `--ssh`. Read `--help` before assuming a
flag; this table will rot too.

## Ownership

Disjoint paths so three people can work at once without a merge fight.

**rig-verifier — `experiments/ux/**`.** The bash rig, Linux only, and that limit
is now explicit rather than accidental: it covers behaviour, not platform. Verb
rename, delete scenario 07, convert seeded scenarios to `pair_two`, update the
scenario table in `README.md`. The rig keeps its second job, driving asciinema
for the gallery, which is presentation and does not need assertions.

**new-renewer — Playwright, replacing `experiments/ux/web-scenarios.sh`.** The
cli↔web scenarios 08, 09 and 10. Frontend changes are Playwright-verified here
as a standing rule, so the browser half of the rig should not be bash.

**crypto-guy — `cli/tests/capability_*.rs`.** The security cells, which are the
ones a UX rig is least able to judge. Highest priority is the revoked ×
direct-blocked-fallback cell (#172), which is the 1.0.0 gate and is currently
untested. Then: an expired invitation is refused as expired, a spent single-use
invitation is refused as spent, and a delegated ceiling holds against a signed
auth-key cap rather than against the party being bounded.

**chief-ux — `cli/tests/surface_*.rs`.** Snapshot tests of the non-interactive
surface: help text, the banner, error messages, exit codes. Cheap, runs on all
three platforms in the existing matrix.

## The Windows ceiling

None of the above reaches the bugs currently open on Windows. #197, the doubled
shell prompt after Ctrl-C in the picker, is console behaviour, and the bash rig
runs on Linux. The layer that can express it is a real PTY driven from a Rust
test: `expectrl` pulls in `conpty` on Windows, `portable-pty` is the lower-level
option. Not yet assigned. Until it is, Windows is verified by a human on a
hosted build, and we should say so out loud rather than let a green board imply
otherwise.

## Requirements

Grouped as the CLI groups itself. Owner in brackets.

**Start.** `init` is idempotent [rig]. `add` mints and the far side claiming
derives the same channel with no key crossing the server [rig]. `add --for
device` and `--for person` differ in the caps they carry [crypto-guy]. `join`
claims a bounded invitation, and one minted before 0.8.4 is refused with a
message rather than a parse error [crypto-guy]. Expired is refused as expired
[crypto-guy]. Spent is refused as spent [crypto-guy]. `id` lists exactly the
devices that certified [rig].

**Share.** `send` plus `receive <code>`, sha256 verified [rig]. `send --to`
needs no code, proves identity, sha256 verified [rig]. `send --to` an unknown
device fails clearly [chief-ux]. `receive` with no code finds a nearby sender
[rig]. `shell` is denied until `grant shell` [rig]. `shell --ssh` reuses real
ssh [rig]. `reach` reports direct vs relay and an rtt [rig]. `forward` carries
traffic, and a busy local port gives a real message rather than `os error 98`,
which is a known open gap [chief-ux]. `expose` publishes a port [rig]. `mount`
lists remote files and survives non-UTF-8 names [rig].

**Serve.** `up` attached receives [rig]. `up --install` autostarts at logon
without admin [Windows, unassigned]. `up --detach` backgrounds with no service
manager [rig]. `up` with a daemon already running follows it instead of starting
a second [rig]. `down` stops only the daemon it targets, through the right
manager, **tested with both a system-managed and a user-managed daemon**, since
a single-unit test passes either way [rig]. `logs -f` follows and Ctrl-C
detaches without stopping the daemon [rig]. `reset` wipes local state only [rig].

**Devices.** list, rename, forget [rig]. Forgetting one device leaves another's
caps intact [rig]. `grant` then `revoke` stops the capability at the gate
[crypto-guy]. A revoked device cannot fall back to a direct path [crypto-guy,
#172]. `requests` approves and denies, and a denial sticks [crypto-guy].

**Cross-cutting.** Every transfer verifies sha256 [rig]. A killed link resumes
and keeps partials [rig]. Relay vs direct is labelled honestly [rig]. The banner
matches clap [chief-ux, exists already, caught `forward`]. Every launcher entry
reaches a real screen, and no entry disappears without an explicit allowlist
entry [chief-ux, this is the test #198 needed].
