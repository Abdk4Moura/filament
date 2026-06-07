// useFilament — the single hook the UI consumes.
//
// It owns all the networking (config fetch, signaling, a PeerLink per peer) and
// exposes a flat, render-friendly snapshot plus a handful of actions. The shape
// returned here IS the contract documented in CONTRACT.md and handed to Claude
// Design. The visual layer should depend only on this shape — never on the
// socket, the RTCPeerConnection, or anything below.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createSignaling } from './signaling.js'
import { PeerLink, politeRole } from './webrtc.js'
import { api } from './api.js'
import { tel, telPeer, installTel, flush as telFlush } from './tel.js'

// Peer display names draw from the same 64x64 vocabulary as the server's
// one-time codes (backend/signaling.py — keep in sync). 4,096 combinations
// picked via crypto.getRandomValues, persisted per tab: a device KEEPS its
// name on purpose (stable identity, like the uid below) — recurrence across
// visits is sessionStorage, not a small or biased RNG. See the variance
// analysis repo for the entropy/birthday math.
const ADJ = [
  'amber', 'bold', 'brave', 'brisk', 'calm', 'cheery', 'chill', 'civil',
  'clever', 'cosy', 'crisp', 'daring', 'deft', 'dewy', 'eager', 'early',
  'fancy', 'fiery', 'fleet', 'fond', 'frank', 'free', 'fresh', 'gentle',
  'giddy', 'glad', 'golden', 'grand', 'happy', 'hardy', 'hasty', 'honest',
  'humble', 'jolly', 'keen', 'kind', 'lively', 'loyal', 'lucky', 'lunar',
  'mellow', 'merry', 'mighty', 'misty', 'neat', 'noble', 'perky', 'plucky',
  'polar', 'proud', 'quick', 'quiet', 'rapid', 'rosy', 'royal', 'shiny',
  'snappy', 'solid', 'spry', 'stout', 'sunny', 'swift', 'tidy', 'witty',
]
const ANIMALS = [
  'otter', 'panda', 'falcon', 'lynx', 'koala', 'heron', 'fox', 'ibex',
  'marten', 'tapir', 'badger', 'beaver', 'bison', 'bongo', 'camel', 'civet',
  'condor', 'crane', 'dingo', 'dove', 'eland', 'ermine', 'ferret', 'finch',
  'gecko', 'gibbon', 'hare', 'hawk', 'hyrax', 'jackal', 'kestrel', 'kiwi',
  'lemur', 'llama', 'macaw', 'magpie', 'mole', 'moose', 'murre', 'newt',
  'ocelot', 'okapi', 'oriole', 'osprey', 'owl', 'pika', 'plover', 'puffin',
  'quokka', 'rabbit', 'raven', 'robin', 'seal', 'shrew', 'skink', 'sparrow',
  'stoat', 'swan', 'tern', 'toucan', 'vole', 'wombat', 'wren', 'zebra',
]

function cryptoPick(a) {
  const buf = new Uint32Array(1)
  // rejection sampling: no modulo bias even for non-power-of-two lists
  const limit = Math.floor(0xffffffff / a.length) * a.length
  do {
    crypto.getRandomValues(buf)
  } while (buf[0] >= limit)
  return a[buf[0] % a.length]
}

function randomName() {
  try {
    const saved = sessionStorage.getItem('filament.name')
    if (saved) return saved
    const name = `${cryptoPick(ADJ)}-${cryptoPick(ANIMALS)}`
    sessionStorage.setItem('filament.name', name)
    return name
  } catch {
    return `${cryptoPick(ADJ)}-${cryptoPick(ANIMALS)}`
  }
}

// Deterministic hue so a peer keeps the same color everywhere it appears.
function hueFor(seed) {
  let h = 0
  for (const c of String(seed)) h = (h * 31 + c.charCodeAt(0)) % 360
  return h
}
const colorFor = (seed) => `hsl(${hueFor(seed)} 70% 55%)`

// Stable per-tab identity (survives reconnects; sids don't). Basis for resume.
function tabUid() {
  try {
    let u = sessionStorage.getItem('filament.uid')
    if (!u) {
      u = (crypto.randomUUID && crypto.randomUUID()) || Math.random().toString(36).slice(2) + Date.now().toString(36)
      sessionStorage.setItem('filament.uid', u)
    }
    return u
  } catch {
    return Math.random().toString(36).slice(2) + Date.now().toString(36)
  }
}

function roomFromUrl() {
  const m = window.location.pathname.match(/^\/rooms\/([^/]+)/)
  return m ? decodeURIComponent(m[1]) : null
}

export function useFilament() {
  const [me, setMe] = useState(null)
  const [peers, setPeers] = useState([]) // [{ id, name, color, status }]
  const [transfers, setTransfers] = useState([]) // see CONTRACT.md
  const [roomId, setRoomId] = useState(null)
  const roomIdRef = useRef(null) // current room for the rejoin belt (#14)
  const [roomScope, setRoomScope] = useState(null) // 'auto' | 'code' | 'link' | 'pair'
  const [roomCode, setRoomCode] = useState(null) // the speakable one-time code while waiting
  const [network, setNetwork] = useState(null) // 'ipv4' | 'ipv6' | 'raw'
  const [signalingKind, setSignalingKind] = useState(null)
  const [connected, setConnected] = useState(false)
  const [localHelper, setLocalHelper] = useState({ available: false, peers: [] }) // Part C

  const sigRef = useRef(null)
  // Live socket truth for non-render code paths (state in closures goes
  // stale). Set everywhere setConnected is.
  const connectedRef = useRef(false)
  const linksRef = useRef(new Map()) // peerId -> PeerLink
  const transferOwner = useRef(new Map()) // transferId -> peerId
  const cfgRef = useRef(null)
  const myNameRef = useRef(null)
  const myIdRef = useRef(null) // our current socket id, for the politeness tiebreaker (#1)
  const uidRef = useRef(tabUid()) // stable per-tab identity (resume)
  // Resume stores — deliberately OUTLIVE individual PeerLinks (see docs/resilience.md):
  const partialsRef = useRef(new Map()) // transferId -> { received, buffers, size, mime, name }
  const outgoingRef = useRef(new Map()) // transferId -> { file, name, size, mime, peerUid }
  const transferStatusRef = useRef(new Map()) // transferId -> latest status
  const attemptsRef = useRef(new Map()) // peerId -> watchdog retry count (#8)
  const makeLinkRef = useRef(null) // lets onStuck re-create a link without closure cycles
  const prevScopeRef = useRef('auto') // restore the discovery bar after a code is used

  // ---- snapshot helpers (keep React state in sync with the live PeerLinks) --
  const addPeer = useCallback((p) => {
    setPeers((prev) => (prev.some((x) => x.id === p.id) ? prev : [...prev, p]))
  }, [])

  // Update an EXISTING peer only — never re-adds (#3). A late callback from a
  // closed PeerLink must not resurrect a tile we already removed.
  const updatePeer = useCallback((id, patch) => {
    if (patch.status) telPeer(id, patch.status)
    if (patch.route) tel('peer-route', { peer: id.slice(-6), route: patch.route })
    setPeers((prev) => {
      const i = prev.findIndex((x) => x.id === id)
      if (i === -1) return prev
      const next = [...prev]
      next[i] = { ...next[i], ...patch }
      return next
    })
  }, [])

  const removePeer = useCallback((id) => {
    setPeers((prev) => prev.filter((p) => p.id !== id))
  }, [])

  const upsertTransfer = useCallback((t) => {
    transferOwner.current.set(t.id, t.peerId)
    if (t.status) transferStatusRef.current.set(t.id, t.status)
    setTransfers((prev) => {
      const i = prev.findIndex((x) => x.id === t.id)
      if (i === -1) return [t, ...prev]
      const next = [...prev]
      next[i] = { ...next[i], ...t }
      return next
    })
  }, [])

  // ---- create a PeerLink for one remote peer -------------------------------
  const makeLink = useCallback(
    ({ id, name, uid }) => {
      if (linksRef.current.has(id)) return linksRef.current.get(id)
      // Supersede (#10): a tab has exactly ONE live connection. If we already
      // show a tile for this uid under an older sid (zombie registry entry, or
      // peer-joined arriving before peer-left during a reconnect), replace it —
      // never show the same device twice.
      if (uid) {
        for (const [oldId, oldLink] of [...linksRef.current]) {
          if (oldId !== id && oldLink.peerUid === uid) {
            linksRef.current.delete(oldId)
            oldLink.close()
            removePeer(oldId)
            attemptsRef.current.delete(oldId)
          }
        }
      }
      // Perfect-negotiation role (#1): exactly one of each pair is impolite and
      // owns the offer. Compared by the STABLE uid when known (so a stale sid
      // on one side can't produce a both-polite deadlock), else by sid.
      const polite = politeRole({ myUid: uidRef.current, peerUid: uid, myId: myIdRef.current, peerId: id })
      addPeer({ id, name, uid: uid || null, color: colorFor(id), status: 'connecting', route: null, lastSeen: 'now' })
      const link = new PeerLink({
        id,
        name,
        iceServers: cfgRef.current.iceServers,
        chunkSize: cfgRef.current.chunkSize,
        polite,
        peerUid: uid || null,
        stores: { partials: partialsRef.current, outgoing: outgoingRef.current },
        sendSignal: (data) => sigRef.current.signal(id, data),
        onStatus: (status) => updatePeer(id, { status }),
        onTransfer: (t) => upsertTransfer(t),
        onRoute: (route) => updatePeer(id, { route }),
        // Resume: once the channel is open, re-offer any paused sends that were
        // headed to this same device (matched by its stable uid).
        onChannelOpen: () => {
          attemptsRef.current.delete(id) // established — reset watchdog retries
          if (!uid) return
          for (const [tid, entry] of outgoingRef.current) {
            // 'paused' = dropped mid-transfer; 'offered' = the offer fired
            // into a dead link (#12: file picked while the tab was suspended)
            // — both must re-offer on the fresh channel.
            const st = transferStatusRef.current.get(tid)
            if (entry.peerUid === uid && (st === 'paused' || st === 'offered')) {
              link.resumeSend(tid)
            }
          }
        },
        // Watchdog (#8): nothing connected within 15s ⇒ a signaling message was
        // lost (dead-sid relay, suspended peer, swallowed SDP error). Tear down
        // and retry with a fresh link + fresh ICE config; then fail honestly.
        watchdogMs: 15000,
        onStuck: () => {
          linksRef.current.delete(id)
          link.close()
          const n = (attemptsRef.current.get(id) || 0) + 1
          attemptsRef.current.set(id, n)
          if (n <= 2) {
            makeLinkRef.current?.({ id, name, uid })
          } else {
            updatePeer(id, { status: 'failed' })
            // #13 second wind (measured: refocus-time revival ran while the
            // links still read healthy; they decayed to failed seconds later
            // with nothing left to catch them). If we're VISIBLE when a peer
            // finally fails, grant ONE delayed fresh start — covers the
            // "both tabs finally awake but budgets exhausted" rendezvous.
            if (document.visibilityState === 'visible' && !attemptsRef.current.get(id + ':sw')) {
              attemptsRef.current.set(id + ':sw', 1)
              tel('second-wind', { peer: id.slice(-6) })
              setTimeout(() => {
                attemptsRef.current.delete(id)
                if (!linksRef.current.has(id) && document.visibilityState === 'visible') {
                  makeLinkRef.current?.({ id, name, uid })
                }
              }, 2500)
            }
          }
        },
      })
      linksRef.current.set(id, link)
      return link
    },
    [addPeer, updatePeer, upsertTransfer, removePeer],
  )
  makeLinkRef.current = makeLink

  // ---- bootstrap -----------------------------------------------------------
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      const cfg = await fetch(api('/api/config')).then((r) => r.json())
      if (cancelled) return
      cfgRef.current = cfg
      setSignalingKind(cfg.signaling)

      // Auto room ('people near you' via shared network) unless the URL pins one.
      const urlRoom = roomFromUrl()
      let room, scope
      if (urlRoom) {
        room = urlRoom
        scope = urlRoom.startsWith('code-') ? 'code' : 'link'
        if (scope === 'code') setRoomCode(urlRoom.slice(5))
      } else {
        const auto = await fetch(api('/api/room')).then((r) => r.json())
        room = auto.room
        scope = 'auto'
        setNetwork(auto.network)
      }
      if (cancelled) return
      setRoomId(room)
      roomIdRef.current = room
      setRoomScope(scope)

      const sig = await createSignaling(cfg)
      sigRef.current = sig
      installTel(tabUid())
      const myName = randomName()
      myNameRef.current = myName

      sig.on('welcome', ({ id, peers: existing }) => {
        // Idempotent — also fires on every reconnect (a reconnect gives us a
        // fresh sid). Tear down stale peer links from the previous session,
        // then rebuild from the fresh roster.
        myIdRef.current = id // set before makeLink so politeness can be computed (#1)
        linksRef.current.forEach((l) => l.close())
        linksRef.current.clear()
        setPeers([])
        setMe({ id, name: myName, color: colorFor(id) })
        setConnected(true)
        connectedRef.current = true
        existing.forEach((p) => makeLink({ id: p.id, name: p.name, uid: p.uid }))
      })
      sig.on('peer-joined', ({ id, name, uid }) => {
        makeLink({ id, name, uid })
      })
      sig.on('peer-left', ({ id }) => {
        linksRef.current.get(id)?.close()
        linksRef.current.delete(id)
        removePeer(id)
      })
      sig.on('signal', ({ from, data }) => {
        let link = linksRef.current.get(from)
        if (!link) {
          // Only an incoming offer may create a new link — ignore stray answers/
          // candidates from peers we don't know about (#7).
          if (data?.type === 'description' && data.description?.type === 'offer') {
            link = makeLink({ id: from, name: from })
          } else {
            return
          }
        }
        link.enqueueSignal(data) // ordered per-peer dispatch (#2)
      })
      // One-time pairing (#11): the server matched us with the code's other
      // party — the code is burned; move both into the private room.
      sig.on('pair-matched', ({ room }) => {
        setRoomCode(null)
        rejoinRef.current?.(room, 'pair')
      })
      sig.on('pair-used', () => {
        // Our code was claimed: the new person is joining OUR room (we never
        // moved). Clear the code; mint another to add another person.
        setRoomCode(null)
        setRoomScope((s) => (s === 'code' ? prevScopeRef.current || 'auto' : s))
      })
      sig.on('pair-error', ({ error }) => {
        console.warn('pairing failed:', error)
        setRoomCode(null)
        setRoomScope((s) => (s === 'code' ? prevScopeRef.current || 'auto' : s))
      })

      // Reflect transport up/down in the UI (the rejoin itself is automatic),
      // and refresh ICE config on reconnect — TURN creds are time-limited (#9).
      sig.on('status', ({ connected: up }) => {
        tel(up ? 'socket-up' : 'socket-down', {})
        if (!up) telFlush()
        setConnected(up)
        connectedRef.current = up
        if (up) {
          fetch(api('/api/config')).then((r) => r.json()).then((c) => { cfgRef.current = c }).catch(() => {})
          // #14 (measured live: a reconnect produced `connect` with NO join —
          // a roomless ghost whose offers everyone rightly ignored). The
          // layer below has auto-rejoin, but its emit can die in a half-open
          // socket; re-join explicitly on EVERY socket-up. Idempotent
          // server-side.
          if (roomIdRef.current) {
            tel('rejoin-belt', { room: String(roomIdRef.current).slice(0, 8) })
            sig.join(roomIdRef.current, myNameRef.current, uidRef.current)
          }
        }
      })

      sig.join(room, myName, uidRef.current)
    })()
    return () => {
      cancelled = true
      sigRef.current?.leave()
      linksRef.current.forEach((l) => l.close())
      linksRef.current.clear()
    }
  }, [makeLink, removePeer])

  // ---- actions -------------------------------------------------------------
  const sendFiles = useCallback((peerId, fileList) => {
    linksRef.current.get(peerId)?.sendFiles(fileList)
  }, [])

  const acceptTransfer = useCallback((transferId) => {
    const peerId = transferOwner.current.get(transferId)
    linksRef.current.get(peerId)?.acceptTransfer(transferId)
  }, [])

  const declineTransfer = useCallback((transferId) => {
    const peerId = transferOwner.current.get(transferId)
    linksRef.current.get(peerId)?.declineTransfer(transferId)
  }, [])

  const saveTransfer = useCallback(
    (transferId) => {
      const t = transfers.find((x) => x.id === transferId)
      if (!t?.url) return
      const a = document.createElement('a')
      a.href = t.url
      a.download = t.name
      a.click()
    },
    [transfers],
  )

  const clearTransfer = useCallback((transferId) => {
    partialsRef.current.delete(transferId) // dismissing a paused transfer frees its bytes
    outgoingRef.current.delete(transferId)
    transferStatusRef.current.delete(transferId)
    setTransfers((prev) => {
      const t = prev.find((x) => x.id === transferId)
      if (t?.url) URL.revokeObjectURL(t.url)
      return prev.filter((x) => x.id !== transferId)
    })
  }, [])

  // ---- room switching (Part B: pair across networks with a code) -----------
  // (referenced from the bootstrap pair-matched handler via ref)
  // Reuses the live socket: drop the current peers, leave, and re-join. No reload.
  const rejoin = useCallback((newRoomId, scope) => {
    const sig = sigRef.current
    if (!sig) return
    linksRef.current.forEach((l) => l.close())
    linksRef.current.clear()
    setPeers([])
    setConnected(false)
    sig.leave()
    setRoomId(newRoomId)
    roomIdRef.current = newRoomId
    setRoomScope(scope)
    sig.join(newRoomId, myNameRef.current, uidRef.current)
  }, [])

  // One-time pairing (#11): claim a spoken code. On success the server emits
  // pair-matched to BOTH parties and the code is burned forever.
  const rejoinRef = useRef(null)

  const pairWithCode = useCallback((code) => {
    const clean = String(code).trim()
    if (clean) sigRef.current?.pairClaim(clean)
  }, [])

  // Mint a single-use speakable code (or register a chosen keyword). We STAY in
  // the current room while waiting; the big code is shown until it's claimed.
  const generateCode = useCallback(async (keyword) => {
    const sig = sigRef.current
    if (!sig) return null
    const kw = typeof keyword === 'string' ? keyword : null // UI passes the click event
    const t0 = Date.now()
    tel('pair-create-click', { up: connectedRef.current })
    // C24 zombie fix, measured live: a hidden mobile tab's socket dies ~5s
    // after hiding and takes ~4.3s to recover after refocus — exactly when
    // people tap CREATE CODE. So: if the socket is known-dead, reconnect and
    // wait for it first; and if the mint gets no answer in 5s anyway (stale
    // 'connected' flag after a freeze), reconnect and retry ONCE.
    const waitUp = (ms) =>
      new Promise((res) => {
        const iv = setInterval(() => {
          if (connectedRef.current || Date.now() - t0 > ms) {
            clearInterval(iv)
            res(connectedRef.current)
          }
        }, 150)
      })
    if (!connectedRef.current) {
      tel('pair-create-wait-reconnect', {})
      sig.reconnect?.()
      if (!(await waitUp(6000))) {
        tel('pair-create-blocked', { afterMs: Date.now() - t0 })
        telFlush()
        return null
      }
    }
    return new Promise((resolve) => {
      let retried = false
      const arm = () =>
        setTimeout(() => {
          if (!retried) {
            retried = true
            tel('pair-create-retry', { afterMs: Date.now() - t0 })
            sig.reconnect?.()
            waitUp(6000).then(() => {
              watchdog = arm()
              sig.pairCreate(kw)
            })
          } else {
            tel('pair-create-timeout', { afterMs: Date.now() - t0 })
            telFlush()
            resolve(null)
          }
        }, 5000)
      let watchdog = arm()
      sig.on('pair-code', function onCode({ code }) {
        clearTimeout(watchdog)
        tel('pair-create-ok', { rttMs: Date.now() - t0, retried })
        setRoomCode(code)
        setRoomScope((s) => {
          if (s !== 'code') prevScopeRef.current = s
          return 'code'
        })
        resolve(code)
      })
      sig.pairCreate(kw)
    })
  }, [])

  rejoinRef.current = rejoin

  const useAutoRoom = useCallback(async () => {
    setRoomCode(null)
    const auto = await fetch(api('/api/room')).then((r) => r.json())
    setNetwork(auto.network)
    rejoin(auto.room, 'auto')
  }, [rejoin])

  // ---- fresh ICE credentials (#9) ------------------------------------------
  // TURN creds in /api/config are time-limited HMACs; a tab open past their TTL
  // would hand stale creds to NEW links. Keep cfgRef fresh in the background.
  useEffect(() => {
    const t = setInterval(() => {
      fetch(api('/api/config')).then((r) => r.json()).then((c) => { cfgRef.current = c }).catch(() => {})
    }, 10 * 60 * 1000)
    return () => clearInterval(t)
  }, [])

  // ---- resilience: nudge a reconnect when a suspended tab resumes ----------
  // Mobile browsers freeze background tabs and throttle timers, so socket.io's
  // auto-reconnect can stall. When the page becomes visible again, kick it.
  // C21 (brb): going hidden — opening a file picker hides the tab on mobile —
  // tells every connected peer we'll be right back, so they hold the line for
  // the declared window instead of guessing; coming back says so.
  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        sigRef.current?.reconnect?.()
        for (const link of linksRef.current.values()) link.sendBack?.()
        // #13 (measured live): two mobile tabs rarely negotiate while both
        // awake — links that failed while WE were frozen stay failed forever.
        // On refocus: reset retry budgets (incl. second-wind markers — they
        // share this map) and rebuild every dead link.
        attemptsRef.current.clear()
        for (const [id, link] of [...linksRef.current.entries()]) {
          const st = link.pc?.connectionState
          if (st === 'failed' || st === 'closed' || st === 'disconnected') {
            tel('refocus-revive', { peer: id.slice(-6), was: st })
            const { name, peerUid } = { name: link.name, peerUid: link.peerUid }
            link.close()
            linksRef.current.delete(id)
            makeLinkRef.current?.({ id, name, uid: peerUid })
          }
        }
      } else {
        for (const link of linksRef.current.values()) link.sendBrb?.(120)
      }
    }
    document.addEventListener('visibilitychange', onVisibility)
    window.addEventListener('focus', onVisibility)
    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
      window.removeEventListener('focus', onVisibility)
    }
  }, [])

  // ---- Part C: optional native LAN-discovery helper ------------------------
  // If the Filament Local helper (experiments/localsend-discovery) is running,
  // it exposes peers it found on the LAN via mDNS/UDP at 127.0.0.1:53317.
  // Browsers may fetch http://localhost from a secure page, so this lights up
  // automatically when present and stays silent (available:false) when not.
  useEffect(() => {
    let alive = true
    const HELPER = 'http://127.0.0.1:53317/peers'
    const poll = async () => {
      try {
        const res = await fetch(HELPER, { signal: AbortSignal.timeout(800) })
        const data = await res.json()
        if (alive) setLocalHelper({ available: true, peers: data.peers || [] })
      } catch {
        if (alive) setLocalHelper({ available: false, peers: [] })
      }
    }
    poll()
    const t = setInterval(poll, 3000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  const roomUrl = useMemo(
    () => (roomId ? `${window.location.origin}/rooms/${roomId}` : null),
    [roomId],
  )

  return {
    me,
    peers,
    transfers,
    roomId,
    roomUrl,
    roomScope, // 'auto' | 'code' | 'link'
    roomCode, // the 6-char code when in a code room, else null
    network, // 'ipv4' | 'ipv6' | 'raw' — how the auto room was grouped
    signalingKind,
    connected,
    localHelper, // { available, peers } — Part C native LAN discovery
    sendFiles,
    acceptTransfer,
    declineTransfer,
    saveTransfer,
    clearTransfer,
    pairWithCode, // join a code room to pair across networks
    generateCode, // mint a fresh code and switch to it; returns the code
    useAutoRoom, // go back to the 'people near you' auto room
  }
}
