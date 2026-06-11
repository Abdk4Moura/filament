/* CommandPalette — the ⌘K / Ctrl+K quick-launcher (shell-surfacing idea C,
   Phase 3). A keyboard-first overlay over the running app: a search input plus a
   filtered, arrow-navigable list of actions. It owns NO peer/session state — it's
   handed the live peers and the same handlers the DeviceSheet/DiscoveryBar use
   (onOpenShell, onSendFiles, onOpenSheet, onPairWithCode, onGenerateCode), so a
   selection runs exactly the same code path as clicking the equivalent affordance.

   Items are derived per render from the peer roster + a couple of global actions:
     - a shell-capable, ready, remembered device → "Open terminal · <name>"
     - every connected device → "Send files · <name>"  and  "Device actions · <name>"
     - globals → "Pair with code", "Create code"
   Filtering is a simple case-insensitive substring over each item's searchable
   text; ↑/↓ move the highlight (wrapping), Enter runs it, Esc / outside-click /
   the affordance toggle close. Presentation only, on the app's tokens (T/D/accent).
*/

import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

// Build the flat command list from the live roster + globals. Each item:
//   { key, glyph, label, sub, search, run }  — run() performs the action and
// returns true to keep the palette open (default: close).
function buildItems({ peers, onOpenShell, onSendFiles, onOpenSheet, onPairWithCode, onGenerateCode }) {
  const items = []
  for (const p of peers || []) {
    const ready = p.status === 'ready'
    const known = !!p.known
    const name = p.known || p.verified || p.name
    // Open terminal — same gate as the DeviceSheet's primary action.
    if (ready && known && p.shell && onOpenShell) {
      items.push({
        key: 'shell:' + p.id, glyph: '›_', label: 'Open terminal', sub: name,
        search: 'open terminal shell ' + name, run: () => onOpenShell(p),
      })
    }
    // Send files — to any ready device.
    if (ready && onSendFiles) {
      items.push({
        key: 'send:' + p.id, glyph: '⇪', label: 'Send files', sub: name,
        search: 'send files ' + name, run: () => onOpenSheet && onOpenSheet(p, null),
      })
    }
    // Device actions — opens the full per-device sheet (rename/info/forget…).
    if (onOpenSheet) {
      items.push({
        key: 'sheet:' + p.id, glyph: '⋯', label: 'Device actions', sub: name,
        search: 'device actions sheet open ' + name, run: () => onOpenSheet(p, null),
      })
    }
  }
  if (onPairWithCode) {
    items.push({ key: 'g:pair', glyph: '⌘', label: 'Pair with code', sub: 'enter a one-time code',
      search: 'pair with code connect device', global: true, run: () => onPairWithCode() })
  }
  if (onGenerateCode) {
    items.push({ key: 'g:create', glyph: '+', label: 'Create code', sub: 'mint a one-time code to share',
      search: 'create code generate new pair', global: true, run: () => onGenerateCode() })
  }
  return items
}

export default function CommandPalette({
  open, onClose, peers, T, D, accent, font, narrow,
  onOpenShell, onSendFiles, onOpenSheet, onPairWithCode, onGenerateCode,
}) {
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const inputRef = useRef(null)
  const listRef = useRef(null)

  const all = useMemo(
    () => buildItems({ peers, onOpenShell, onSendFiles, onOpenSheet, onPairWithCode, onGenerateCode }),
    [peers, onOpenShell, onSendFiles, onOpenSheet, onPairWithCode, onGenerateCode],
  )
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return all
    return all.filter((it) => it.search.toLowerCase().includes(needle))
  }, [all, q])

  // Reset query + selection and focus the input each time it opens.
  useEffect(() => {
    if (open) {
      setQ('')
      setSel(0)
      // focus after the portal mounts
      const t = setTimeout(() => inputRef.current && inputRef.current.focus(), 0)
      return () => clearTimeout(t)
    }
  }, [open])

  // Keep the highlight in range as the filtered set shrinks.
  useEffect(() => { setSel((s) => (filtered.length ? Math.min(s, filtered.length - 1) : 0)) }, [filtered.length])

  if (!open) return null

  const run = (it) => {
    if (!it) return
    const keepOpen = it.run()
    if (!keepOpen) onClose()
  }

  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); onClose(); return }
    if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => (filtered.length ? (s + 1) % filtered.length : 0)); return }
    if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => (filtered.length ? (s - 1 + filtered.length) % filtered.length : 0)); return }
    if (e.key === 'Enter') { e.preventDefault(); run(filtered[sel]); return }
  }

  // Scroll the highlighted row into view on keyboard nav.
  const rowRef = (i) => (el) => {
    if (el && i === sel) el.scrollIntoView({ block: 'nearest' })
  }

  const panel = (
    <div
      data-testid="cmd-palette"
      ref={listRef}
      onClick={(e) => e.stopPropagation()}
      onKeyDown={onKey}
      style={{
        width: narrow ? 'calc(100vw - 32px)' : 540, maxWidth: 'calc(100vw - 24px)',
        background: T.panel, border: '1px solid ' + T.line,
        boxShadow: '0 22px 60px rgba(0,0,0,.55)', display: 'flex', flexDirection: 'column',
        maxHeight: narrow ? '70vh' : 460, overflow: 'hidden',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '12px 14px', borderBottom: '1px solid ' + T.line }}>
        <span style={{ color: accent, fontSize: 13, fontWeight: 700, flexShrink: 0 }}>⌘K</span>
        <input
          ref={inputRef}
          data-testid="cmd-input"
          value={q}
          onChange={(e) => { setQ(e.target.value); setSel(0) }}
          placeholder="Search devices and actions…"
          style={{
            flex: 1, minWidth: 0, font: 'inherit', fontSize: 14, color: T.text,
            background: 'transparent', border: 'none', outline: 'none', letterSpacing: '.01em',
          }}
        />
        <span style={{ fontSize: 10, color: T.faint, flexShrink: 0 }}>esc</span>
      </div>
      <div data-testid="cmd-list" style={{ overflowY: 'auto', minHeight: 0, padding: 6 }}>
        {filtered.length === 0 ? (
          <div style={{ padding: '22px 12px', fontSize: 12.5, color: T.dim, textAlign: 'center' }}>No matches</div>
        ) : (
          filtered.map((it, i) => {
            const active = i === sel
            return (
              <div
                key={it.key}
                ref={rowRef(i)}
                data-testid="cmd-item"
                data-cmd-active={active ? '1' : '0'}
                onClick={() => run(it)}
                onMouseMove={() => setSel(i)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 11, padding: '10px 11px', cursor: 'pointer',
                  border: '1px solid ' + (active ? accent : 'transparent'),
                  background: active ? (it.global ? accent + '14' : (T.mode === 'light' ? 'rgba(0,0,0,.03)' : 'rgba(255,255,255,.04)')) : 'transparent',
                  transition: 'background .1s, border-color .1s',
                }}
              >
                <span style={{ width: 20, flexShrink: 0, textAlign: 'center', fontSize: 13, fontWeight: it.global ? 700 : 500, color: it.global || active ? accent : T.sub }}>{it.glyph}</span>
                <span style={{ flex: 1, minWidth: 0 }}>
                  <span style={{ display: 'block', fontSize: 13.5, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{it.label}</span>
                  {it.sub && <span style={{ display: 'block', fontSize: 11, color: T.dim, marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{it.sub}</span>}
                </span>
                {active && <span style={{ fontSize: 10, color: T.faint, flexShrink: 0 }}>↵</span>}
              </div>
            )
          })
        )}
      </div>
    </div>
  )

  return createPortal(
    <div
      data-testid="cmd-scrim"
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 5000, font: '13px ' + font,
        background: 'rgba(0,0,0,.45)', display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
        paddingTop: narrow ? '12vh' : '14vh',
      }}
    >
      {panel}
    </div>,
    document.body,
  )
}
