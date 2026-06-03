// Placeholder UI — proves the contract end to end (discovery, send, accept,
// progress, save). Claude Design replaces this whole file with the real square
// interface; it should consume exactly the same useQuickshare() shape.

import { useRef, useState } from 'react'
import { useQuickshare } from './lib/useQuickshare.js'

export default function App() {
  const qs = useQuickshare()
  const fileInput = useRef(null)
  const [target, setTarget] = useState(null)
  const [copied, setCopied] = useState(false)

  const pickFilesFor = (peerId) => {
    setTarget(peerId)
    fileInput.current.click()
  }
  const onFiles = (e) => {
    if (target && e.target.files.length) qs.sendFiles(target, e.target.files)
    e.target.value = ''
  }
  const copyLink = async () => {
    await navigator.clipboard.writeText(qs.roomUrl)
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }

  return (
    <div className="qs">
      <header className="qs-bar">
        <div className="qs-brand">quickshare</div>
        <div className="qs-me">
          {qs.me ? (
            <>
              <span className="dot" style={{ background: qs.me.color }} />
              {qs.me.name}
            </>
          ) : (
            'connecting…'
          )}
          <span className="qs-kind">{qs.signalingKind}</span>
        </div>
        <button className="qs-link" onClick={copyLink} disabled={!qs.roomUrl}>
          {copied ? 'copied!' : 'copy room link'}
        </button>
      </header>

      <main className="qs-grid">
        {qs.peers.length === 0 && (
          <p className="qs-empty">
            No one here yet. Open this room link on another device or tab to pair.
          </p>
        )}
        {qs.peers.map((p) => (
          <button
            key={p.id}
            className={`qs-peer ${p.status}`}
            onClick={() => p.status === 'ready' && pickFilesFor(p.id)}
            title={p.status === 'ready' ? 'Send files' : p.status}
          >
            <span className="qs-avatar" style={{ background: p.color }}>
              {p.name?.[0]?.toUpperCase()}
            </span>
            <span className="qs-name">{p.name}</span>
            <span className="qs-status">{p.status}</span>
          </button>
        ))}
      </main>

      {qs.transfers.length > 0 && (
        <section className="qs-transfers">
          {qs.transfers.map((t) => (
            <div key={t.id} className="qs-transfer">
              <div className="qs-tinfo">
                <span className="qs-arrow">{t.direction === 'send' ? '↑' : '↓'}</span>
                <span className="qs-fname">{t.name}</span>
                <span className="qs-fsize">{fmtBytes(t.size)}</span>
                <span className="qs-tstatus">{t.status}</span>
              </div>
              <div className="qs-progress">
                <div className="qs-bar2" style={{ width: `${Math.round(t.progress * 100)}%` }} />
              </div>
              <div className="qs-actions">
                {t.direction === 'receive' && t.status === 'offered' && (
                  <>
                    <button onClick={() => qs.acceptTransfer(t.id)}>accept</button>
                    <button onClick={() => qs.declineTransfer(t.id)}>decline</button>
                  </>
                )}
                {t.direction === 'receive' && t.status === 'complete' && (
                  <button onClick={() => qs.saveTransfer(t.id)}>save</button>
                )}
                {(t.status === 'complete' || t.status === 'declined') && (
                  <button onClick={() => qs.clearTransfer(t.id)}>clear</button>
                )}
              </div>
            </div>
          ))}
        </section>
      )}

      <input ref={fileInput} type="file" multiple hidden onChange={onFiles} />
    </div>
  )
}

function fmtBytes(n) {
  if (!n) return ''
  const u = ['B', 'KB', 'MB', 'GB']
  let i = 0
  while (n >= 1024 && i < u.length - 1) (n /= 1024), i++
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`
}
