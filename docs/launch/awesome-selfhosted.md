# awesome-selfhosted PR — prepared entry

**Target file:** `awesome-selfhosted/awesome-selfhosted-data` repo →
`software/filament.yml` (the list is data-driven now; PRs add a YAML file).

**Proposed entry:**

```yaml
name: "Filament"
website_url: "https://filament.autumated.com"
source_code_url: "https://github.com/Abdk4Moura/filament"
description: "Browser-to-browser P2P file transfer (WebRTC) with automatic same-network discovery, one-time pairing codes, resumable transfers, and visible routing (LAN/P2P/relay)."
licenses:
  - MIT
platforms:
  - Docker
  - Python
  - Nodejs
tags:
  - File Transfer & Synchronization
```

**Prerequisites before opening the PR (their requirements):**
- [x] Repo must have an explicit LICENSE file — MIT LICENSE at repo root
      since 2026-06 (© 2023-2026 Abdk4Moura) ✓
- [ ] RELEASE must be ≥ 4 months old (their bot checks the latest release
      date, not git history) — v1.0.0 published 2026-06-06, so eligible
      2026-10-06; a scheduled routine opens the PR then (branch staged at
      Abdk4Moura/awesome-selfhosted-data@add-filament)
- [ ] Demo link available ✓ (the live instance)

**Action for Claude when approved:** add LICENSE to filament repo, fork
`awesome-selfhosted/awesome-selfhosted-data` under Abdk4Moura, add the YAML,
open the PR. Needs explicit go-ahead since the PR is public under your name.
