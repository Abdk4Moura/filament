# Per-device tile interaction — v2 (post-ship, form-factor-divergent)

**Status:** design only. No code in this change. A separate agent is working in
`runner/` + `cli/`; this doc touches nothing there.

**What this is.** We shipped **model H** (tap/left-click a tile sends instantly; a
tile `⋯` button + desktop right-click open a per-device `DeviceSheet` with
Open terminal / Send files / Rename / Forget / Info). We have now *used* it. This
doc folds real-usage feedback back into the model and **re-opens the A↔H decision**
— concluding that the right answer is **divergent**: mobile leans **tap → sheet**
(model A), desktop leans **something richer than either** (hover-revealed inline
actions + double-click-to-send + ⌘K), and the two share one component set.

**Supersedes** the relevant parts of `docs/design/shell-surfacing-ux.md` §4/§5
(which recommended "A + H triggers folded in, parity-first"). The parity bet was
wrong in one direction: it under-served touch (the `⋯` target) and under-served
desktop (which can do better than a popover). This doc keeps everything else from
that doc — the SHELL badge, the shared `DeviceSheet`, the lazy SESSIONS strip, the
⌘K palette — and only changes the **trigger model per form factor**.

---

## 0. The seed — what the user said after using model H

1. **On mobile the `⋯` is too small a touch target.** They want **tapping the
   tile to open the bottom sheet** — the sheet (Open terminal / Send files /
   Rename / Info) becomes the *primary* mobile interaction.
2. **Drag-and-drop onto a tile must STILL send instantly.** The fast path is
   sacred and stays.
3. **Desktop can be made even better** — don't force mobile's model onto desktop;
   give desktop its own, richer treatment.

So (1) is "adopt A on mobile," (3) is "invent the best desktop model," and (2) is
the invariant that survives both.

---

## 1. Current shipped state (model H) — exact handlers

Read against the code on `main`:

### `frontend/src/ui/Filament.jsx` — `PeerTile({ peer, onSendFiles, onOpenSheet, … })`
- **`onClick`** → `ready && inp.current.click()` — opens the OS file picker (SEND).
- **`onContextMenu`** → `if (showMore) { preventDefault(); openSheet() }` — desktop
  right-click opens the sheet.
- **`onDragOver`/`onDrop`** → `onSendFiles(peer.id, files)` — direct send (no sheet).
- **`⋯` button** (`showMore = ready && known && onOpenSheet`) → `e.stopPropagation();
  openSheet()`. It is a **24×22px** flex item top-right. *This is the too-small
  touch target.*
- `openSheet = () => onOpenSheet(peer, tileRef.getBoundingClientRect())` — passes the
  tile rect so the desktop popover can anchor.
- Chips: `REMEMBERED` (dashed), `SHELL` (`isMachine = !!peer.shell`), `RouteBadge`
  (dropped when both identity chips present), `StatusDot`.
- **Gating quirk that matters:** `showMore` requires `known`. A *stranger* (unknown,
  un-remembered) peer has **no sheet trigger at all** today — tap just sends, and
  there is no Rename/Forget/terminal to offer anyway. Keep this.

### `frontend/src/ui/DeviceSheet.jsx`
- Row order today: **`Open terminal`** (primary, accent, gated `ready && known &&
  peer.shell && onOpenShell`) → **`Send files`** → **`Rename`** (if `known &&
  onRename`) → **`Forget device`** (danger, if `known && onForget`), then an **Info**
  block. `Send files` row's hidden `<input>` is internal to the sheet.
- Mobile = bottom sheet (scrim, drag-handle, swipe-down>70px to dismiss, Esc).
  Desktop = anchored popover from `anchorRect`, viewport-clamped, flips up near the
  bottom edge. One component, `narrow` branches the shell.
- **Note:** `Open terminal` is the auto-primary *first* row; `Send files` is the
  *second*. That ordering is fine when the sheet is the **secondary** surface (model
  H). It is **wrong** once the sheet becomes the **primary** mobile surface — there,
  Send must be first (see §2).

### `frontend/src/ui/CommandPalette.jsx`
- ⌘K / Ctrl+K. `buildItems` yields per ready peer: `Open terminal` (gated like the
  sheet), `Send files` (→ `onOpenSheet(p, null)`), `Device actions` (→ sheet);
  globals `Pair with code`, `Create code`. Arrow-nav, substring filter, Enter runs.
- A visible `⌘K` `paletteBtn` sits in both top bars (discoverable; doubles as the
  mobile launcher).

### Root wiring (`Filament` default export)
- `openSheet = (peer, rect) => setSheet({ peer, rect })`; `sheetPeer` re-derived from
  the live roster each render.
- `openSession`/`SessionsStrip`/`activeSessionId` — the Phase-2 session model
  (multiple terminals, backgrounded panes kept mounted to preserve the PTY).
- Mobile grid `repeat(2,minmax(0,1fr))`; desktop `repeat(auto-fill,minmax(150px,1fr))`.

Everything below is expressed as deltas against exactly these handlers.

---

## 2. MOBILE — adopt **tap → sheet** (model A), Send-first, peek-fast

### Recommended interaction (triggers → result)

| Trigger | Result |
|---|---|
| **Tap a tile** | Open the `DeviceSheet` bottom sheet (NOT the picker). |
| **Drag a file onto a tile** | Send directly (unchanged) — where touch DnD works. |
| **Tap `Send files` row** (1st, largest) | OS file picker → send → sheet closes. |
| **Tap `Open terminal`** (if `peer.shell`) | Open session overlay. |
| **Tap Rename / Forget / Info** | As today, in-sheet. |
| **Swipe-down / scrim-tap / Esc** | Dismiss. |
| **Long-press a tile** | *(optional, deferred)* fast-send shortcut — see §2.3. |

The `⋯` button is **removed on mobile** (the whole tile is now the trigger), which
deletes the too-small-target complaint at the root.

### Mock — mobile grid (app vocabulary)

```
┌───────────────────────────────┐
│ filament  [a7c]      ⌘K ● ◐    │
├───────────────────────────────┤
│ peers (3)        transfers (1) │
├───────────────────────────────┤
│ tap a tile for actions         │   ← hint copy changes (was "to send a file")
│ ┌────────────┐ ┌────────────┐  │
│ │■ REM·SHELL ●│ │■        ●   │  │
│ │      do-vm  │ │      mina   │  │   no ⋯ on the tile anymore
│ │ready · LAN  │ │ready        │  │
│ │tap → actions│ │tap → actions│  │
│ └────────────┘ └────────────┘  │
└───────────────────────────────┘
        ▼ tap "do-vm"
┌───────────────────────────────┐
│            ▂▂▂▂▂   (handle)    │
│ ■ do-vm   REMEMBERED  SHELL  ● │
│ LAN · ready · seen just now    │
│ ┌───────────────────────────┐  │
│ │ ⇪  Send files             │  │ ← FIRST, largest, accent-primary, autofocus
│ │     pick files to send    │  │
│ └───────────────────────────┘  │
│ ┌───────────────────────────┐  │
│ │ ›_ Open terminal          │  │ ← only if peer.shell (secondary now)
│ └───────────────────────────┘  │
│ ┌───────────────────────────┐  │
│ │ ✎  Rename                 │  │
│ └───────────────────────────┘  │
│ ⊘ Forget device                │
│ INFO  route LAN · shell capable│
└───────────────────────────────┘
```

### The 90/10 send-path analysis (the crux)

On mobile, touch DnD is unreliable, so for most users "send a file" is no longer
"drag" — it's **tap-tile → tap Send = 2 taps** (model H was 1 tap). That is the one
real regression, and it must be mitigated hard, because **send is the 90% verb** on
the phone:

1. **`Send files` becomes the FIRST, largest, accent-primary, auto-focused row.**
   This is a row-order swap in `DeviceSheet` *for the mobile branch / when the sheet
   is the primary surface*. The second tap lands where the thumb already is (bottom
   of screen) on a deliberately fat target. Two taps, but the second is near-zero
   cost / muscle-memory.
2. **The sheet must feel like a *peek*, not a modal.** Open fast (existing
   `transform .18s ease-out` is good), no spinner, render the picker-launching row
   immediately. Subjectively this reads closer to "1.2 taps" than "2 taps."
3. **Drag-drop still sends instantly** (invariant #2) for the minority of mobile
   browsers / tablet+pointer setups where it works.
4. **Optional long-press = instant send** (§2.3) as an *accelerator for the power
   user*, never the only path — it's undiscoverable, so it can't carry the 90%.

Net: we pay one extra, cheap tap on send to make **all four actions reachable by one
comfortable full-tile tap** instead of a 24px `⋯`. Given the feedback explicitly
asks for this, and given Send is made the first/fat/autofocus row, this is the right
trade on touch.

### Discoverability
- **Excellent.** The entire tile is the trigger; the hint line changes to
  `tap a tile for actions` (and the grid sub-hint from `tap a tile to send a file`
  → `tap a tile for actions`). Nothing hides behind a 24px glyph.
- SHELL/REMEMBERED chips still mark machines at rest (unchanged), so users know
  *before* tapping which devices offer a terminal.

### Pros / cons (mobile A)
- **Pros:** kills the small-target complaint; one consistent gesture for *every*
  action; naturally extensible; the sheet is already built and on-theme.
- **Cons:** +1 tap on the 90% send path (mitigated above); relies on the row-order
  swap so Send doesn't sit below Open-terminal.

### §2.3 Optional: long-press = instant send (deferred accelerator)
A long-press (≈350ms) on a tile could fire the picker directly (`inp.click()`),
giving power users back the 1-gesture send without a visible affordance. Risks:
collides with the platform text-selection/callout gesture and with the ergonomics
doc's long-press vocabulary; undiscoverable. **Decision: design it in, ship it later
behind the core change**, with a one-time hint ("hold to send fast") surfaced in the
sheet. Do not let it gate Phase 1.

---

## 3. DESKTOP — make it genuinely better: **hover-actions + dbl-click send + ⌘K**

Desktop has hover, a cursor, a keyboard, and right-click — none of which mobile has.
Forcing the mobile "click → sheet" model onto desktop would *add* a click to the 90%
send path on the platform where the single-click send is most beloved and where DnD
already works great. So desktop **diverges**: keep single-click cheap, reveal the
rich actions on hover, and let power users live in the keyboard.

### Recommended interaction (triggers → result)

| Trigger | Result |
|---|---|
| **Single left-click tile body** | Send (open picker) — **unchanged from H.** |
| **Drag-drop onto tile** | Send directly — unchanged. |
| **Hover a tile** | Reveal an inline **action bar** at the tile's bottom edge: a `›_` terminal chip (if `peer.shell`) and a `⋯ more` chip. One hover, then one click — no popover round-trip for the common secondary action. |
| **Click the hovered `›_` chip** | Open terminal directly (skips the sheet). |
| **Click the hovered `⋯ more` chip** OR **right-click anywhere on the tile** | Open the `DeviceSheet` popover (Rename / Forget / Info + the same actions). |
| **Double-click tile body** | Also Send (explicit, discoverable via the hover hint) — a safety/redundancy for users who learn "double-click = send" elsewhere; single-click already sends, so this is harmless reinforcement, not a mode. |
| **`⌘K` / `Ctrl+K`** | Command palette (unchanged) — the keyboard-first path for everything. |
| **Arrow keys / Enter on the grid** *(deferred, §3.4)* | Keyboard-navigate tiles; Enter = send, `T` = terminal, `⋯`/context-menu key = sheet. |

Why hover-reveal instead of mobile's sheet-first: it preserves the **1-click send**
(no regression for the 90% on desktop), and it makes the **most common secondary
action (open terminal) a single hovered click** rather than click→popover→click. The
sheet stays the home for the *long tail* (rename/forget/info) and for right-click
muscle memory.

### Mock — desktop grid at rest vs hover

```
 RESTING                              HOVER on "do-vm"
┌──────────┐ ┌──────────┐            ┌──────────┐
│■ REM SH ●│ │■      ●   │            │■ REM SH ●│   ← tile lifts (translateY -2)
│   do-vm  │ │   mina   │            │   do-vm  │
│ready·LAN │ │ready     │            │ready·LAN │
│          │ │          │            │┌────────┐│   ← action bar fades in on hover
└──────────┘ └──────────┘            ││›_  ⋯   ││      ›_ = open terminal (peer.shell)
                                     │└────────┘│      ⋯  = device actions (sheet)
                                     └──────────┘
```

Right-click anywhere on the tile → the existing `DeviceSheet` popover, anchored to
the tile (the `onContextMenu` path already exists; we keep it):

```
 right-click "do-vm" →  ┌──────────────────────────┐
                        │ ■ do-vm  REMEMBERED SHELL │
                        │ LAN · ready               │
                        │ ⇪ Send files              │  (Send-first OR terminal-first?
                        │ ›_ Open terminal          │   see §5 — desktop keeps terminal
                        │ ✎ Rename                  │   primary since click already sends)
                        │ ⊘ Forget device           │
                        │ INFO route LAN · shell ✓  │
                        └──────────────────────────┘
```

### The 90/10 send-path analysis (desktop)
- **Send stays 1 action** (single-click *or* drag-drop) — **zero regression**, which
  is the whole point of diverging. This is strictly better than dragging mobile's
  sheet-first model onto desktop (which would make send a 2-click action here).
- **Open terminal becomes 1 hover + 1 click** (down from H's hover-find-the-`⋯` →
  click → sheet → click = effectively 2 clicks). The hovered `›_` chip is the
  biggest concrete win of the desktop model.
- Long-tail actions (rename/forget/info) are 1 hover + 1 click (`⋯ more`) or 1
  right-click — same ballpark as H, but now discoverable via the always-on-hover bar.

### Discoverability (desktop)
- Hover bar makes the secondary actions **visible on the natural gesture** (mousing
  toward a tile) — far better than a static 24px `⋯`.
- Right-click is a bonus path for those with the habit; it's not the *only* way in
  (which is the discoverability flaw it has alone).
- `⌘K` button in the top bar advertises the palette.
- SHELL chip still marks machines at rest.

### Pros / cons (desktop hover model)
- **Pros:** no send regression; terminal is a single hovered click; rich actions
  discoverable on hover; right-click + ⌘K layer on for power users; reuses the
  existing `DeviceSheet` and `onContextMenu`.
- **Cons:** hover bar is new tile chrome (must not re-introduce the old layout
  overlap — render it as a real flex/absolute element with reserved space, fading
  opacity only, never reflowing the hint line); no hover on touch (fine — desktop
  only); the hover bar overlaps the bottom hint line, so on hover we **swap** the
  hint line *for* the action bar (don't stack them) — this is the one layout rule to
  get right.

### §3.4 Deferred desktop power-ups (design-in, ship later)
- **Keyboard grid nav:** roving-tabindex over tiles; `Enter`=send, `t`=terminal,
  `r`=rename, context-menu key / `Shift+F10` = sheet. Pairs with the existing ⌘K.
- **Multi-select batch send:** `Shift`/`Ctrl`-click to select multiple tiles, then
  one picker sends to all selected. High value for "push this build to 3 boxes."
  Needs `onSendFiles` to accept a peer-id list (a backend/hook change — out of scope
  for the doc's frontend delta, flagged for a follow-up).
- **Persistent right-rail detail panel** *instead of* the popover: reuse the
  transfers column to show the selected device's actions inline. Rejected as the
  *default* (steals transfer real estate, and the popover is lighter), but noted as a
  "pinned device" option later.

---

## 4. Divergence vs parity — the explicit call

**Decision: diverge the TRIGGER, share the COMPONENTS.**

The original doc valued form-factor parity and chose one model (tap→send + ⋯/sheet)
for both. Real usage shows the platforms have *opposite* ergonomic constraints:

- **Mobile:** no hover, no cheap precise small-target, unreliable DnD → the *whole
  tile* must be the action trigger, and **send costs a tap** no matter what, so we
  might as well route through the sheet (which makes every action equal-cost). →
  **tap → sheet (A).**
- **Desktop:** hover + cursor + keyboard + reliable DnD → single-click send is free
  and loved; revealing actions on hover is free; a popover/right-click/⌘K are all
  available. → **click sends, hover/right-click/⌘K for the rest (richer-than-H).**

Parity would force one side to eat the other's tax (either +1 click on desktop send,
or a fiddly hover/`⋯` on mobile). So we **diverge the trigger** and **keep the
substance shared:**

- **One `DeviceSheet`** — same component, same action set, same styling; only the
  *thing that opens it* differs (mobile: tile tap; desktop: `⋯`-chip / right-click).
- **One action vocabulary** — Open terminal / Send files / Rename / Forget / Info —
  identical wherever it appears (sheet, hover chip, palette).
- **One session model + one ⌘K palette** — both already form-factor-agnostic.

This is divergence at the *interaction layer* over a *shared model layer* — the
cheapest possible way to honor the feedback without forking the codebase.

---

## 5. Action set & ordering — primary per context

The action set is settled: **Open terminal · Send files · Rename · Forget · Info**.
What changes is *which is primary*, and that is now **context-dependent**:

| Context | Primary (first / accent / autofocus) | Then | Notes |
|---|---|---|---|
| **Mobile sheet** (sheet is the *only* way to act) | **Send files** | Open terminal (if shell) · Rename · Forget · Info | Send is the 90% verb and the sheet is its only door → it must lead. **Row-order swap vs today.** |
| **Desktop sheet/popover** (click already sends) | **Open terminal** (if shell) | Send files · Rename · Forget · Info | Click+drag already cover send, so the sheet leads with the action you *came to the sheet for*. Matches today's order — keep. |
| **Desktop hover bar** | `›_` terminal chip (if shell) + `⋯ more` | — | Only these two; everything else lives one click deeper in the sheet. |
| **Shell-capable device** | terminal offered (chip + primary row) | | gated `ready && known && peer.shell`. |
| **Non-shell device** | no terminal anywhere | | sheet shows Send/Rename/Forget/Info only. |
| **Stranger (unknown) device** | Send only | | keep today's gate: no `known` ⇒ no Rename/Forget/terminal. On mobile, tapping a stranger tile can go **straight to the picker** (no sheet — there's nothing else to offer), preserving 1-tap send for strangers. |

So the row order is **not** a fixed constant — `DeviceSheet` takes a `primary`
(or `sendFirst`) prop driven by `narrow`. Concretely: **mobile ⇒ Send first;
desktop ⇒ terminal first** (today's order).

---

## 6. RECOMMENDATION (decisive)

- **Mobile:** **tap tile → `DeviceSheet` (model A)**, with **Send files as the
  first/largest/accent/auto-focused row**, the sheet opening as a fast peek;
  **drag-drop still sends directly**; **remove the `⋯` button** on mobile; stranger
  tiles tap straight to the picker. (Long-press fast-send deferred.)
- **Desktop:** **single-click sends (unchanged)**; **hover reveals an inline action
  bar** (`›_` terminal chip if `peer.shell`, `⋯ more` chip) so terminal is one
  hovered click and the sheet is one hovered click; **right-click still opens the
  sheet**; **double-click = send** (reinforcement); **⌘K** unchanged. (Keyboard grid
  nav + multi-select batch send deferred.)
- **Shared:** one `DeviceSheet`, one action set, one session model, one palette.
  Diverge the *trigger*, not the substance.
- **Sheet ordering:** `sendFirst` on mobile (Send leads), terminal-first on desktop
  (today's order).

This honors all three pieces of feedback exactly: mobile gets tap→sheet; DnD still
sends instantly everywhere; desktop gets a richer, send-preserving model that is
strictly better than H.

---

## 7. Implementation delta from CURRENT code (shippable steps)

All gated on the existing `ready` / `known` / `peer.shell` checks. Frontend-only;
no `runner/`/`cli/`/daemon changes. Steps are independently shippable.

### Step 1 — `DeviceSheet`: parameterize row order (`sendFirst`)
- `frontend/src/ui/DeviceSheet.jsx`: add a `sendFirst` prop. When true, render the
  **`Send files`** `ActionRow` **first and as `tone="primary"`** (accent), and the
  `Open terminal` row second (non-primary). When false, keep today's order
  (terminal primary first). Auto-focus the first row's button on mobile so the
  second tap is immediate.
- No other sheet changes; Rename/Forget/Info stay.

### Step 2 — Mobile: tile tap opens the sheet; drop still sends; drop the `⋯`
- `Filament.jsx` `PeerTile`: thread the existing `narrow` down to the tile (or read
  it) so the tile can branch. On **mobile**:
  - `onClick` → `openSheet()` **instead of** `inp.current.click()`, **except** when
    the peer is a stranger (`!known` ⇒ keep `inp.click()` direct-send, since the
    sheet would have nothing but Send).
  - **do not render the `⋯` button** (remove from the mobile branch).
  - keep `onDragOver`/`onDrop` → `onSendFiles` exactly as-is (invariant #2).
- Root: pass `sendFirst={narrow}` to `DeviceSheet` (Step 1).
- Copy: change the mobile grid hint `tap a tile to send a file` → `tap a tile for
  actions`; change the tile bottom hint line to `tap → actions` on mobile.

### Step 3 — Desktop: hover action bar + double-click send (keep single-click send)
- `PeerTile` desktop branch:
  - keep `onClick` → `inp.click()` (send) and `onContextMenu` → `openSheet()`.
  - add `onDoubleClick` → `inp.click()` (explicit send reinforcement).
  - on **hover** (`hov`), render a bottom **action bar** that **replaces the hint
    line** (swap, don't stack — render the action bar *or* the hint, never both, to
    avoid the historical overlap):
    - a `›_` chip (only if `ready && known && peer.shell`) → `e.stopPropagation();
      onOpenSheet`'s sibling `onOpenShell`/`openSession(peer)` directly. (Thread an
      `onOpenShell`/`openSession` into `PeerTile`, or reuse `onOpenSheet` + have the
      chip call a new `onOpenTerminal` prop wired to `openSession`.)
    - a `⋯ more` chip → `e.stopPropagation(); openSheet()`.
  - keep the existing `⋯`-as-flex-item removed on desktop in favor of the hover bar
    (or retain a faint `⋯` for non-hover/keyboard users — optional).
- Root: pass an `onOpenTerminal={openSession}` prop to `PeerTile` for the hover `›_`
  chip (the handler already exists as `openSession`).

### Step 4 — Sheet primary per platform (already covered by Step 1's `sendFirst`)
- Confirm: mobile `sendFirst=true` (Send leads); desktop `sendFirst=false` (terminal
  leads, today's order). Driven by `narrow` at the call site.

### Step 5 (deferred, separate PRs) — accelerators
- Mobile long-press = instant send (one-time hint in the sheet).
- Desktop keyboard grid nav (roving tabindex; Enter=send, `t`=terminal, sheet key).
- Desktop multi-select batch send — **requires `onSendFiles` to accept a list of
  peer ids** (hook/backend change; flag for follow-up, out of this frontend delta).

### What explicitly does NOT change
- `WebTerminal.jsx`, the SESSIONS strip, the session model, `CommandPalette.jsx`
  (the palette already routes through `openSheet`/`openSession` and stays as-is),
  the drag-drop send path, the SHELL/REMEMBERED/route chips, all gating.

---

## 8. One-paragraph summary for the build agent

Diverge the *trigger*, keep the *components*. **Mobile:** make a full-tile **tap open
the `DeviceSheet`** (remove the 24px `⋯`), with **Send files as the first, fat,
accent, auto-focused row** (new `sendFirst` prop on `DeviceSheet`, true when
`narrow`); strangers tap straight to the picker; **drag-drop still sends instantly**.
**Desktop:** leave **single-click = send** (no regression), add a **hover action bar**
on the tile that **replaces the hint line** with a `›_` open-terminal chip
(`peer.shell` only) and a `⋯ more` chip → sheet, keep **right-click → sheet** and add
**double-click = send**; ⌘K unchanged. The sheet, action set, session model and
palette are shared; only the way you open the sheet differs per platform. Touch
points: `PeerTile.onClick`/`onDoubleClick`/hover-bar and the new `sendFirst` prop on
`DeviceSheet`; the terminal handler is the already-wired `openSession`. Defer
long-press fast-send, keyboard grid nav, and multi-select batch send.
