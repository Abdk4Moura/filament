// Predictive / local echo (mosh-style) for the web-shell terminal.
//
// In the raw-PTY bridge, xterm does NOT echo what you type: a typed char only
// becomes visible when the server sends it back via onPtyData. On a slow or
// blippy link that round-trip is the lag (and the freeze) you feel. This layer
// paints the keystroke IMMEDIATELY, styled (dim + underline), then reconciles
// when the server's authoritative bytes arrive: a match drops the styling (it
// becomes real), a divergence or a timeout erases the prediction so the display
// always converges to the server's truth.
//
// CORRECTNESS FIRST. A wrong prediction that corrupts the screen is worse than
// no prediction, so this is deliberately conservative:
//   - prediction is a pure overlay: the real key is ALWAYS sent to the PTY by
//     the caller regardless of what we draw, so we never change what the shell
//     receives, only what the user sees a few ms sooner.
//   - we only predict in the NORMAL screen buffer; in the alternate screen (a
//     TUI like vim/htop/opencode that draws its own frames) we predict nothing.
//   - we start with prediction OFF and only turn it on after we OBSERVE the
//     server echoing our recent keystrokes verbatim (mosh's echo confidence).
//     This naturally disables prediction at password prompts (no echo) and in
//     non-echoing programs.
//   - we only predict printable ASCII and a Backspace that deletes a char we
//     ourselves just predicted (still unconfirmed). Control keys, Enter, arrows,
//     Tab, Ctrl-sequences and pastes are passed straight through for the server.
//   - every prediction has a timeout; an unconfirmed one is erased so a lost
//     keystroke never leaves a ghost.
//
// MODEL. We keep a small model of the predicted TAIL of the current line: an
// anchor cell (where the predicted run begins) and the predicted string. Any
// change (a char, a backspace) updates the string and REPAINTS the tail (move to
// anchor, clear to end of line, write the styled string). When server bytes
// arrive we rewind the cursor to the anchor, clear to end of line, drop the
// model, then let the caller write the authoritative bytes from the anchor. So
// the server's truth (including its own backspace echoes) always renders cleanly
// over a blanked region: a transient may flicker but the screen always converges
// to exactly what the server sent. We never layer authoritative bytes on top of
// stale styled cells, and we never double-apply an erase.

// SGR styling for a predicted (not-yet-confirmed) cell: dim + underline. Reset
// after the run so nothing leaks into authoritative output we write.
const PREDICT_ON = '\x1b[2m\x1b[4m'
const PREDICT_OFF = '\x1b[0m'

const PRINTABLE = (ch) => ch.length === 1 && ch >= ' ' && ch <= '~'
const BACKSPACE = (d) => d === '\x7f' || d === '\b'

// Confidence levels. We only paint predictions at CONFIRMED. TENTATIVE means we
// have sent input and are waiting to see if the server echoes it; once it does,
// we promote to CONFIRMED and begin painting. A contradiction drops us back.
const OFF = 0       // no echo observed yet (or just contradicted): predict nothing
const TENTATIVE = 1 // saw input go out, probing whether the server echoes it
const CONFIRMED = 2 // server echoed our input verbatim: safe to predict

export class PredictiveEcho {
  // term: the xterm Terminal. opts.enabled: gate (default true). opts.timeoutMs:
  // per-prediction erase timeout. opts.now: injectable clock (tests).
  constructor(term, opts = {}) {
    this.term = term
    this.enabled = opts.enabled !== false
    this.timeoutMs = opts.timeoutMs || 1000
    this.now = opts.now || (() => Date.now())
    this.confidence = OFF
    // The predicted tail model. anchor = {x,y} absolute cell where the run starts
    // (null when nothing is predicted). text = the predicted chars after anchor.
    // t = timestamp of the OLDEST still-unconfirmed char, for the timeout.
    this.anchor = null
    this.text = ''
    this.t = 0
    // recently-sent input chars we are waiting to see echoed back, for the
    // echo-confidence probe. Small ring; only printable chars go here.
    this.probe = []
    this._timer = 0
  }

  // Back-compat / test convenience: expose the pending predictions as an array.
  get pending() {
    if (!this.anchor) return []
    const out = []
    for (let i = 0; i < this.text.length; i++) {
      out.push({ ch: this.text[i], x: this.anchor.x + i, y: this.anchor.y, t: this.t })
    }
    return out
  }

  // True only when it is SAFE to predict right now: enabled and not in a TUI's
  // alternate screen.
  _canPredict() {
    if (!this.enabled) return false
    const b = this.term && this.term.buffer && this.term.buffer.active
    if (!b) return false
    if (b.type === 'alternate') return false // a TUI owns the screen, never predict
    return true
  }

  // Cursor cell as absolute buffer coordinates (x = column, y = absolute row).
  _cursor() {
    const b = this.term.buffer.active
    return { x: b.cursorX, y: b.baseY + b.cursorY }
  }

  // Caller hook: a key the USER typed. We may paint a prediction. The caller still
  // sends the real key to the PTY regardless. `composing` true => an IME
  // composition is mid-flight; never predict then (the committed text is handled
  // on compositionend via onUserText, so we do not double-insert).
  onUserKey(data, composing) {
    if (composing) return
    if (PRINTABLE(data)) {
      this._recordProbe(data)
      this._predictChar(data)
    } else if (BACKSPACE(data)) {
      this._predictBackspace()
    } else if (data === '\r' || data === '\n') {
      // Enter submits the line; let the server drive. Forget the model WITHOUT
      // erasing (the styled cells are about to scroll into history as the server
      // echoes the newline; repainting would fight it).
      this.clear()
    }
    // Any other non-printable (arrows, Tab, Ctrl-*, Esc, paste): predict nothing,
    // leave the existing model to reconcile or time out.
  }

  // Caller hook for committed IME text (compositionend). Each char is a probe and
  // a possible prediction, exactly like typing it, with no composing guard.
  onUserText(text) {
    if (!text) return
    for (const ch of text) {
      if (PRINTABLE(ch)) { this._recordProbe(ch); this._predictChar(ch) }
    }
  }

  _recordProbe(ch) {
    this.probe.push(ch)
    if (this.probe.length > 24) this.probe.shift()
  }

  _predictChar(ch) {
    if (this.confidence !== CONFIRMED) return // not yet trusted: do not draw
    if (!this._canPredict()) return
    const b = this.term.buffer.active
    if (!this.anchor) {
      // Start a new predicted run at the live cursor. Conservative: only same-line
      // tail typing; if we are at the last column, a wrap would break our flat
      // model, so skip and let the server render it.
      if (b.cursorX >= this.term.cols - 1) return
      this.anchor = this._cursor()
      this.text = ''
      this.t = this.now()
    } else {
      // Continuing a run: bail (and repaint clean) if it would overflow the line.
      if (this.anchor.x + this.text.length >= this.term.cols - 1) return
    }
    this.text += ch
    this._repaint()
    this._arm()
  }

  _predictBackspace() {
    if (this.confidence !== CONFIRMED) return
    if (!this._canPredict()) return
    // We ONLY shorten a tail WE just predicted (still unconfirmed). We never
    // optimistically delete a real, server-rendered char: that could corrupt, so
    // if there is no predicted text we predict nothing and let the server's own
    // backspace echo do the delete at normal latency.
    if (!this.anchor || !this.text.length) return
    this.text = this.text.slice(0, -1)
    this._repaint()
    if (!this.text.length) { this.anchor = null; this._disarmIfEmpty() }
    // Drop the deleted char from the echo probe: it will never be confirmed now.
    if (this.probe.length) this.probe.pop()
  }

  // Repaint the predicted tail: move to the anchor, clear to end of line, write
  // the styled run, then park the cursor at the end of the run (where the next
  // char / the server's echo will land). One write batch, so no visible flicker.
  _repaint() {
    if (!this.anchor) return
    const b = this.term.buffer.active
    const vrow = this.anchor.y - b.baseY
    if (vrow < 0 || vrow >= this.term.rows) { // scrolled out of view: give up safely
      this.anchor = null; this.text = ''
      return
    }
    const cup = `\x1b[${vrow + 1};${this.anchor.x + 1}H`
    this.term.write(cup + '\x1b[0m\x1b[K' + (this.text ? PREDICT_ON + this.text + PREDICT_OFF : ''))
  }

  // Server bytes arrived (authoritative). Update echo confidence from the probe,
  // then reconcile the model against this output. Returns the bytes UNCHANGED for
  // the caller to write; we never alter the authoritative stream.
  onServerData(u8) {
    const s = typeof u8 === 'string' ? u8 : decodeAscii(u8)
    this._updateConfidence(s)
    this._reconcile(s)
    return u8
  }

  // Echo confidence (mosh idea): if the server's output contains our recently
  // sent chars in order, it is echoing us, so raise confidence; OFF -> TENTATIVE
  // -> CONFIRMED. We match leniently (the echo may be interleaved with prompt
  // redraw bytes) by consuming probe chars as we find them in order. If we sent
  // chars and NONE appear (a password prompt), we do not promote.
  _updateConfidence(s) {
    if (!this.probe.length) return
    let pi = 0
    for (let i = 0; i < s.length && pi < this.probe.length; i++) {
      if (s[i] === this.probe[pi]) pi++
    }
    if (pi > 0) {
      this.probe.splice(0, pi)
      if (this.confidence < CONFIRMED) this.confidence += 1
    }
  }

  // Reconcile the predicted model against authoritative output. We predicted by
  // advancing the cursor, so the server's echo bytes (written by the caller right
  // after this) assume the ORIGINAL cursor position; without rewinding, a
  // confirmed echo would render one cell too far right (a doubled char). So we
  // always: rewind to the anchor, clear to end of line (wiping our styled cells),
  // and drop the model. The authoritative bytes then redraw the tail from truth.
  // If the prediction matched, the redraw is the same chars (seamless within one
  // write batch). If it diverged, the server's version wins and we drop confidence
  // so we stop predicting until echo re-establishes.
  _reconcile(s) {
    if (!this.anchor) return
    // Does the leading printable run of the output match our predicted text?
    let matched = 0, si = 0
    while (matched < this.text.length && si < s.length) {
      const c = s[si]
      if (!PRINTABLE(c)) { si++; continue } // tolerate interleaved control bytes
      if (c === this.text[matched]) { matched++; si++ }
      else break
    }
    const fullMatch = matched === this.text.length && this.text.length > 0
    // Rewind + clear so the authoritative bytes overwrite from the anchor.
    const b = this.term.buffer.active
    const vrow = this.anchor.y - b.baseY
    if (vrow >= 0 && vrow < this.term.rows) {
      this.term.write(`\x1b[${vrow + 1};${this.anchor.x + 1}H\x1b[0m\x1b[K`)
    }
    this.anchor = null; this.text = ''
    this._disarmIfEmpty()
    if (!fullMatch) {
      this.confidence = OFF
      this.probe = []
    }
  }

  // If we flip into a TUI (alternate screen) or get disabled with a model
  // outstanding, forget it: we cannot safely repaint into a screen we no longer
  // own, and the server's frames will overwrite the cells anyway. Called by the
  // caller after each authoritative write.
  syncBuffer() {
    if (this.anchor && !this._canPredict()) {
      this.anchor = null; this.text = ''
      this._disarmIfEmpty()
    }
  }

  // Per-prediction timeout: erase the model if its oldest char has gone
  // unconfirmed past timeoutMs (a lost keystroke must not leave a ghost).
  _arm() {
    if (this._timer) return
    this._timer = setInterval(() => this._sweep(), Math.max(100, Math.floor(this.timeoutMs / 4)))
  }
  _disarmIfEmpty() {
    if (!this.anchor && this._timer) { clearInterval(this._timer); this._timer = 0 }
  }
  _sweep() {
    if (!this.anchor) { this._disarmIfEmpty(); return }
    if (this.t <= this.now() - this.timeoutMs) {
      // Expired unconfirmed: erase the styled tail and reset confidence.
      const b = this.term.buffer.active
      const vrow = this.anchor.y - b.baseY
      if (vrow >= 0 && vrow < this.term.rows) {
        this.term.write(`\x1b[${vrow + 1};${this.anchor.x + 1}H\x1b[0m\x1b[K`)
      }
      this.anchor = null; this.text = ''
      this.confidence = OFF
      this.probe = []
      this._disarmIfEmpty()
    }
  }

  // Forget the model WITHOUT erasing (used on Enter: the line is submitted, the
  // server will redraw; repainting would fight it).
  clear() {
    this.anchor = null; this.text = ''
    this.probe = []
    this._disarmIfEmpty()
  }

  dispose() {
    if (this._timer) { clearInterval(this._timer); this._timer = 0 }
    this.anchor = null; this.text = ''
    this.probe = []
  }
}

// Minimal byte->string for confidence/reconcile matching. We only care about
// ASCII here (printable echo); non-ASCII bytes become a placeholder that simply
// will not match a prediction, which is the safe outcome.
function decodeAscii(u8) {
  let s = ''
  for (let i = 0; i < u8.length; i++) {
    const b = u8[i]
    s += b < 0x80 ? String.fromCharCode(b) : '�'
  }
  return s
}
