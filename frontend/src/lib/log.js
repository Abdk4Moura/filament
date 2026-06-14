// Leveled console logger: the user-facing console tier of the logging-parity
// work. The UI's ONLY connection surface is the value proposition (DIRECT vs
// RELAY: the route badge + amber relay chip + global "N on relay"). EVERYTHING
// below that tier (the lifecycle firehose tel.js already beacons to ops)
// lives HERE, in the browser console, gated by a level that is QUIET BY
// DEFAULT. A normal user (even with devtools open) sees only warn+/error; a
// power user raises the level to watch the stream.
//
// Raising the level, three ways (query wins, then persists):
//   - ?log=debug   in the URL              (also accepts a number, e.g. ?log=3)
//   - localStorage.setItem('filamentLog','debug')
//   - window.__filamentLog.setLevel('trace')   (live, from devtools)
//
// tel.js is UNCHANGED, it still beacons lifecycle to /api/telemetry for ops.
// log.js is purely the console tier; the two are independent.

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3, trace: 4 }
const NAMES = ['error', 'warn', 'info', 'debug', 'trace']
const DEFAULT = LEVELS.warn // quiet by default

// Map a name OR a numeric string to a level number; null if unrecognised.
function parseLevel(v) {
  if (v == null) return null
  const s = String(v).trim().toLowerCase()
  if (s in LEVELS) return LEVELS[s]
  if (/^[0-4]$/.test(s)) return Number(s)
  return null
}

// Resolve the initial level once: ?log= query param wins (and persists to
// localStorage so it survives reloads), else localStorage, else DEFAULT.
function resolveLevel() {
  let fromQuery = null
  try {
    const q = new URLSearchParams(window.location.search).get('log')
    fromQuery = parseLevel(q)
  } catch {}
  if (fromQuery != null) {
    try {
      localStorage.setItem('filamentLog', NAMES[fromQuery])
    } catch {}
    return fromQuery
  }
  let fromStore = null
  try {
    fromStore = parseLevel(localStorage.getItem('filamentLog'))
  } catch {}
  return fromStore != null ? fromStore : DEFAULT
}

let level = resolveLevel()

// Emit at `lvl` only if it's at or below the current level. Each line is tagged
// `[filament]` plus a short scope so the firehose is greppable in devtools.
function emit(lvl, method, scope, args) {
  if (lvl > level) return
  const tag = scope ? `[filament:${scope}]` : '[filament]'
  // eslint-disable-next-line no-console
  console[method](tag, ...args)
}

// A scoped logger binds a short scope tag (e.g. 'rtc', 'sig', 'pair') to every
// line. `log` itself is the unscoped root.
function make(scope) {
  return {
    error: (...a) => emit(LEVELS.error, 'error', scope, a),
    warn: (...a) => emit(LEVELS.warn, 'warn', scope, a),
    info: (...a) => emit(LEVELS.info, 'info', scope, a),
    debug: (...a) => emit(LEVELS.debug, 'debug', scope, a),
    trace: (...a) => emit(LEVELS.trace, 'debug', scope, a), // console.debug: trace floods a stack
    scope: (s) => make(s),
    setLevel,
    getLevel: () => NAMES[level],
    get level() {
      return level
    },
  }
}

// Raise/lower the level live. Accepts a name ('debug') or a number (3). Persists
// so a refresh keeps it. Returns the resolved level name (or the prior one on a
// bad value).
function setLevel(name) {
  const n = parseLevel(name)
  if (n == null) return NAMES[level]
  level = n
  try {
    localStorage.setItem('filamentLog', NAMES[n])
  } catch {}
  return NAMES[n]
}

export const log = make(null)

// Expose for flipping live in devtools: window.__filamentLog.setLevel('trace').
try {
  if (typeof window !== 'undefined') {
    window.__filamentLog = {
      setLevel,
      getLevel: () => NAMES[level],
      get level() {
        return level
      },
      levels: { ...LEVELS },
    }
  }
} catch {}
