// AnnotationOverlay: a dev-only "draw arrows on the live UI and send it to Claude"
// tool. Toggle with the floating ✎ button (or Shift+A). Draw arrows / boxes /
// freehand + a note, hit Send → it screenshots the page (html2canvas), composites
// your strokes, and POSTs to the Vite dev endpoint /__annotate, which drops a PNG
// + note into frontend/.annotations/ for Claude to read. No-op in production.
import React, { useEffect, useRef, useState, useCallback } from 'react'

const COLORS = ['#FF3B5C', '#7CF6C8', '#FFC857', '#5BE7FF', '#FF8AD6', '#FFFFFF']
const TOOLS = [
  { id: 'arrow', label: '↗ arrow' },
  { id: 'box', label: '▢ box' },
  { id: 'pen', label: '✎ pen' },
]

function drawStroke(ctx, s) {
  ctx.strokeStyle = s.color
  ctx.fillStyle = s.color
  ctx.lineWidth = 3
  ctx.lineCap = 'round'
  ctx.lineJoin = 'round'
  if (s.tool === 'pen') {
    ctx.beginPath()
    s.pts.forEach((p, i) => (i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y)))
    ctx.stroke()
    return
  }
  const a = s.pts[0]
  const b = s.pts[s.pts.length - 1]
  if (s.tool === 'box') {
    ctx.strokeRect(Math.min(a.x, b.x), Math.min(a.y, b.y), Math.abs(b.x - a.x), Math.abs(b.y - a.y))
    return
  }
  // arrow
  ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
  const ang = Math.atan2(b.y - a.y, b.x - a.x)
  const h = 14
  ctx.beginPath()
  ctx.moveTo(b.x, b.y)
  ctx.lineTo(b.x - h * Math.cos(ang - Math.PI / 7), b.y - h * Math.sin(ang - Math.PI / 7))
  ctx.lineTo(b.x - h * Math.cos(ang + Math.PI / 7), b.y - h * Math.sin(ang + Math.PI / 7))
  ctx.closePath(); ctx.fill()
}

export default function AnnotationOverlay() {
  const [on, setOn] = useState(false)
  const [tool, setTool] = useState('arrow')
  const [color, setColor] = useState(COLORS[0])
  const [strokes, setStrokes] = useState([])
  const [note, setNote] = useState('')
  const [status, setStatus] = useState('')
  const canvasRef = useRef(null)
  const drawing = useRef(null)
  const toolbarRef = useRef(null)
  // keep live refs so the canvas redraw always sees current tool/color
  const toolRef = useRef(tool); toolRef.current = tool
  const colorRef = useRef(color); colorRef.current = color

  // Shift+A toggles (ignore when typing in an input/textarea)
  useEffect(() => {
    const onKey = (e) => {
      const t = e.target
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)
      if (e.shiftKey && (e.key === 'A' || e.key === 'a') && !typing) { e.preventDefault(); setOn((v) => !v) }
      if (e.key === 'Escape' && on) setOn(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [on])

  const sizeCanvas = useCallback(() => {
    const c = canvasRef.current
    if (!c) return
    c.width = window.innerWidth
    c.height = window.innerHeight
  }, [])

  const redraw = useCallback(() => {
    const c = canvasRef.current
    if (!c) return
    const ctx = c.getContext('2d')
    ctx.clearRect(0, 0, c.width, c.height)
    strokes.forEach((s) => drawStroke(ctx, s))
    if (drawing.current) drawStroke(ctx, drawing.current)
  }, [strokes])

  useEffect(() => { if (on) { sizeCanvas(); redraw() } }, [on, sizeCanvas, redraw])
  useEffect(() => { redraw() }, [strokes, redraw])
  useEffect(() => {
    const r = () => { sizeCanvas(); redraw() }
    window.addEventListener('resize', r)
    return () => window.removeEventListener('resize', r)
  }, [sizeCanvas, redraw])

  const pt = (e) => {
    const t = e.touches ? e.touches[0] : e
    return { x: t.clientX, y: t.clientY }
  }
  const start = (e) => {
    if (toolbarRef.current && toolbarRef.current.contains(e.target)) return
    e.preventDefault()
    drawing.current = { tool: toolRef.current, color: colorRef.current, pts: [pt(e)] }
  }
  const move = (e) => {
    if (!drawing.current) return
    e.preventDefault()
    const p = pt(e)
    if (drawing.current.tool === 'pen') drawing.current.pts.push(p)
    else drawing.current.pts = [drawing.current.pts[0], p]
    redraw()
  }
  const end = () => {
    if (!drawing.current) return
    const s = drawing.current
    drawing.current = null
    if (s.pts.length > 1 || s.tool === 'pen') setStrokes((arr) => [...arr, s])
  }

  const send = async () => {
    setStatus('capturing…')
    try {
      const { default: html2canvas } = await import('html2canvas')
      // hide our own UI for the shot
      const c = canvasRef.current
      const tb = toolbarRef.current
      const prevC = c.style.display, prevT = tb.style.display
      c.style.display = 'none'; tb.style.display = 'none'
      const shot = await html2canvas(document.body, { backgroundColor: '#0A0B0C', scale: 1, logging: false, useCORS: true })
      c.style.display = prevC; tb.style.display = prevT
      // composite strokes (CSS px == scale 1)
      const ctx = shot.getContext('2d')
      strokes.forEach((s) => drawStroke(ctx, s))
      const png = shot.toDataURL('image/png')
      setStatus('sending…')
      const res = await fetch('/__annotate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ png, note, url: location.href, w: window.innerWidth, h: window.innerHeight }),
      })
      const j = await res.json().catch(() => ({}))
      setStatus(j.ok ? `sent → ${j.file}` : 'send failed')
      setTimeout(() => setStatus(''), 4000)
    } catch (e) {
      setStatus('error: ' + (e && e.message))
      setTimeout(() => setStatus(''), 5000)
    }
  }

  // floating toggle when off
  if (!on) {
    return (
      <button onClick={() => setOn(true)} title="annotate (Shift+A)" style={{
        position: 'fixed', right: 14, bottom: 76, zIndex: 9999, width: 42, height: 42, borderRadius: 42,
        border: '1px solid rgba(255,255,255,.16)', background: 'rgba(20,22,26,.82)', color: '#7CF6C8',
        fontSize: 18, cursor: 'pointer', backdropFilter: 'blur(8px)', boxShadow: '0 6px 20px rgba(0,0,0,.5)',
      }}>✎</button>
    )
  }

  return (
    <>
      <canvas
        ref={canvasRef}
        onMouseDown={start} onMouseMove={move} onMouseUp={end} onMouseLeave={end}
        onTouchStart={start} onTouchMove={move} onTouchEnd={end}
        style={{ position: 'fixed', inset: 0, zIndex: 9998, cursor: 'crosshair', touchAction: 'none' }}
      />
      <div ref={toolbarRef} style={{
        position: 'fixed', right: 14, bottom: 76, zIndex: 9999, display: 'flex', flexDirection: 'column', gap: 8,
        padding: 12, width: 232, background: 'rgba(16,18,21,.92)', border: '1px solid rgba(255,255,255,.12)',
        backdropFilter: 'blur(12px)', borderRadius: 12, boxShadow: '0 12px 40px rgba(0,0,0,.6)',
        fontFamily: "'JetBrains Mono',ui-monospace,monospace", color: '#D9DEE3', fontSize: 12,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ letterSpacing: '.08em', color: '#9AA1A8', fontSize: 11 }}>ANNOTATE</span>
          <span onClick={() => setOn(false)} style={{ cursor: 'pointer', color: '#666C73' }}>✕</span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {TOOLS.map((t) => (
            <button key={t.id} onClick={() => setTool(t.id)} style={{
              flex: 1, padding: '6px 4px', cursor: 'pointer', fontFamily: 'inherit', fontSize: 11,
              border: `1px solid ${tool === t.id ? '#7CF6C8' : '#1E2227'}`, color: tool === t.id ? '#06120D' : '#9AA1A8',
              background: tool === t.id ? '#7CF6C8' : 'transparent',
            }}>{t.label}</button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 7 }}>
          {COLORS.map((cc) => (
            <button key={cc} onClick={() => setColor(cc)} style={{
              width: 22, height: 22, borderRadius: 22, cursor: 'pointer', background: cc, padding: 0,
              border: color === cc ? '2px solid #D9DEE3' : '2px solid transparent',
            }} />
          ))}
        </div>
        <textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="note for Claude…" rows={2}
          style={{
            resize: 'none', background: '#0A0B0C', color: '#D9DEE3', border: '1px solid #1E2227', padding: 8,
            fontFamily: 'inherit', fontSize: 12, outline: 'none',
          }} />
        <div style={{ display: 'flex', gap: 6 }}>
          <button onClick={() => setStrokes((a) => a.slice(0, -1))} style={btn('#1E2227', '#9AA1A8')}>undo</button>
          <button onClick={() => setStrokes([])} style={btn('#1E2227', '#9AA1A8')}>clear</button>
          <button onClick={send} style={{ ...btn('#7CF6C8', '#06120D'), flex: 1, fontWeight: 600 }}>send → Claude</button>
        </div>
        {status && <div style={{ fontSize: 11, color: '#7CF6C8' }}>{status}</div>}
      </div>
    </>
  )
}

const btn = (bg, fg) => ({
  padding: '7px 10px', cursor: 'pointer', fontFamily: 'inherit', fontSize: 11,
  border: `1px solid ${bg}`, background: bg === '#1E2227' ? 'transparent' : bg, color: fg,
})
