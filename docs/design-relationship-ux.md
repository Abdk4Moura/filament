# Relationship UX: derived states, code-addressable verbs, guests

> Status: design, 2026-09-17. Docs only, no Rust. Companion pieces:
> `CONTRACT.md` (wire-visible frames) and `docs/ux-tickets.md` (the build order).
>
> This file is being written in the open. The skeleton lands first so the PR
> exists from the first commit; the sections fill in behind it.

## Why

Filament has the pieces of a relationship model scattered across five places:
a pair secret in `devices.json`, an owner-signed certificate, a capability
store, a roster, and a set of tiers computed for display. There is no single
account of what a relationship IS, how it deepens, how it decays, and what the
other side sees while it changes. This document is that account.

## Sections to come

1. The state model (states x transitions).
2. The verb surface (existing / changed / new) with transcripts.
3. Derivation rules: tiers as views over ledger verdicts plus facts.
4. The non-interactive contract for every prompt.
5. What the counterpart sees next.
6. Open questions.
