# Nudges: an error should name the next command

> Status: proposed UX guidance. Not a normative CLI reference.

## The bug that started this

`filament add` in a script said:

    ✗ add is interactive (it needs consent on both ends). For automation,
      create a bounded invitation instead:
          filament add --for device

That suggested command fails with the same message. `--out` is required too, so
the error told you to run the thing that produced it. It was a hardcoded string
in `fleet_ui/pair_ui.rs`, never checked against the path it describes.

A suggested command is a CLAIM ABOUT BEHAVIOUR. This one was wrong and nothing
could have noticed, because no test reads error text.

## The principle

A refusal should answer "what do I do now" for the thing the operator was
evidently trying, not restate the rule they broke.

Three properties, in order of how much they cost when missing:

1. **Every suggested command must run.** Otherwise the error is worse than
   silence: it spends the reader's trust and their next minute.
2. **The suggestion is relative to the attempt.** Someone who typed
   `add laptop` already said who; do not re-explain `--for`, name the one piece
   they missed. Someone who typed bare `add` has not chosen yet, so enumerate.
3. **Name the other end.** An invitation whose reader does not know that
   `filament join <file>` claims it is not a working instruction. Half a
   ceremony is not guidance.

The third matters most for AGENTS, which cannot infer the claim side from
context the way a person browsing `--help` might.

## Prior art worth stealing

**rustc / clippy** is the richest model. A diagnostic is structured, not a
string: primary message, spans, `note:`, `help:`, and suggestions that each
carry an APPLICABILITY (`MachineApplicable`, `MaybeIncorrect`,
`HasPlaceholders`). That is what lets `cargo fix` apply them and
`--error-format=json` emit `suggested_replacement` for tooling. The
machine-readable half is exactly the agent case.

Crucially rustc's UI tests capture the FULL diagnostic including every `help:`,
so a suggestion that stopped working shows up as a test diff. Our bug is
structurally impossible there.

**git** has an explicit advice subsystem: `advice.*` config keys, each hint
individually silenceable (`advice.detachedHead`, `advice.pushNonFastForward`).
The insight is that nudges need an off switch or experts learn to ignore all
output, which costs you the messages that matter.

**Rust crates**: `miette` (diagnostic errors with help text, related
diagnostics, severity, source snippets) is the closest drop-in; `ariadne` is a
similar renderer. `clap` already does did-you-mean for typo'd flags via strsim,
but nothing attempt-relative.

**Elsewhere**: `oclif` errors carry a literal `suggestions: string[]`.
`kubectl`, `npm` and `deno` do similarity-based command suggestions.
`clig.dev` (Command Line Interface Guidelines) is the design-side reference and
says errors should suggest next steps, without giving you code.

## What this repo should do

Not adopt a framework yet. The cheap, specific fix is a small internal type so
suggestions stop being ad-hoc strings:

    Nudge { what_failed, options: Vec<(intent, command)>, next_step }

Then one test asserts every `command` in every Nudge parses as valid argv. That
kills the whole class, and the pattern already exists here:
`printed_hints_name_verbs_that_exist` does exactly this for the first-screen
menu. It just does not cover error text, which is where the bug was.

If richer output is wanted later (spans, JSON for agents), `miette` is the
adoption path and rustc's applicability levels are the model to copy.

NOTE: crate APIs move; check current `miette` docs before adopting.
