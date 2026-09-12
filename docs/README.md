# Filament documentation map

This directory separates normative references, current planning, designs, and historical working records. Do not treat a dated note or a proposal as a statement about the shipped tree.

## Authority and precedence

1. [`../README.md`](../README.md) — product overview, installation, and first-use paths.
2. [`../CONTRACT.md`](../CONTRACT.md) — **normative** cross-component protocol and UI contract. Update it only for shipped, interoperable behavior.
3. [`status/CURRENT.md`](status/CURRENT.md) — **canonical current-state index**, verified against a named commit.
4. [`../ROADMAP.md`](../ROADMAP.md) — **canonical ordered backlog**. It contains commitments, not a historical log.
5. [`../CHANGELOG.md`](../CHANGELOG.md) — release history.

If sources disagree, verify against the tree and current tests, correct the higher-authority document, and link the older document to its successor.

## Status convention

Every nontrivial design, plan, investigation, and status record must state a status near its title:

- **canonical** — maintained reference for current behavior or policy
- **active** — approved work in progress; it must also appear in `ROADMAP.md`
- **proposed** — design/idea, not an implementation claim
- **implemented** — implementation record; name the verifying commit, test, or release
- **historical** — preserved context only; re-verify before acting on it
- **superseded** — retained solely for its trail; link the successor

Use `Last verified` and `Verified against` for documents that make source-level claims. Avoid ambiguous labels such as “done” or “current” without evidence.

## By purpose

| Need | Canonical location |
|---|---|
| Product use and installation | `../README.md`, `../cli/README.md` |
| Protocol and browser/CLI interface | `../CONTRACT.md` |
| Routing reference / `filament man routing` source | `../cli/docs/filament-routing.md` |
| Architecture and platform rules | `architecture/`, `adr-*.md` |
| Reliability evidence | `resilience.md`, `cli-resilience.md`, `testing/`, `test-topology-coverage.md` |
| Configuration | `env-vars.md` |
| Deployment and packages | `../deploy/README.md`, `../packaging/` |
| Current state and priorities | `status/CURRENT.md`, `../ROADMAP.md` |
| Designs | `design*.md`, `design/` |
| Security/review records | `security/`, `reviews/` |

## Historical material

`archive/` contains immutable handoffs, investigations, completed plans, and working notes. It exists for traceability, not execution:

- `archive/handoffs/` — dated session and work-state handoffs
- `archive/plans/` — completed or superseded plans
- `archive/notes/` — informal working notes

New root-level dated plans, agendas, and handoffs are not allowed. Put them in the appropriate `docs/` area and give them a status.
