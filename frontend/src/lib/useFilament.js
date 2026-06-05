// useFilament — the single hook the UI consumes.
//
// It owns all the networking (config fetch, signaling, a PeerLink per peer) and
// exposes a flat, render-friendly snapshot plus a handful of actions. The shape
// returned here IS the contract documented in CONTRACT.md and handed to Claude
// Design. The visual layer should depend only on this shape — never on the
// socket, the RTCPeerConnection, or anything below.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createSignaling } from './signaling.js'
import { PeerLink } from './webrtc.js'
import { api } from './api.js'

const ADJ = ['brave', 'calm', 'clever', 'eager', 'gentle', 'jolly', 'keen', 'lucky', 'mellow', 'swift']
const ANIMALS = ['otter', 'panda', 'falcon', 'lynx', 'koala', 'heron', 'fox', 'ibex', 'marten', 'tapir']

function randomName() {
  const pick = (a) => a[Math.floor(Math.random() * a.length)]
  return `${pick(ADJ)}-${pick(ANIMALS)}`
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
  const [roomScope, setRoomScope] = useState(null) // 'auto' | 'code' | 'link'
  const [network, setNetwork] = useState(null) // 'ipv4' | 'ipv6' | 'raw'
  const [signalingKind, setSignalingKind] = useState(null)
  const [connected, setConnected] = useState(false)
  const [localHelper, setLocalHelper] = useState({ available: false, peers: [] }) // Part C

  const sigRef = useRef(null)
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

  // ---- snapshot helpers (keep React state in sync with the live PeerLinks) --
  const addPeer = useCallback((p) => {
    setPeers((prev) => (prev.some((x) => x.id === p.id) ? prev : [...prev, p]))
  }, [])

  // Update an EXISTING peer only — never re-adds (#3). A late callback from a
  // closed PeerLink must not resurrect a tile we already removed.
  const updatePeer = useCallback((id, patch) => {
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
      // Perfect-negotiation role (#1): the peer with the larger id is "polite".
      // Exactly one of each pair is impolite and owns the offer — no glare even
      // when both join/reconnect simultaneously.
      const polite = myIdRef.current ? myIdRef.current > id : true
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
          if (!uid) return
          for (const [tid, entry] of outgoingRef.current) {
            if (entry.peerUid === uid && transferStatusRef.current.get(tid) === 'paused') {
              link.resumeSend(tid)
            }
          }
        },
      })
      linksRef.current.set(id, link)
      return link
    },
    [addPeer, updatePeer, upsertTransfer],
  )

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
      } else {
        const auto = await fetch(api('/api/room')).then((r) => r.json())
        room = auto.room
        scope = 'auto'
        setNetwork(auto.network)
      }
      if (cancelled) return
      setRoomId(room)
      setRoomScope(scope)

      const sig = await createSignaling(cfg)
      sigRef.current = sig
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
      // Reflect transport up/down in the UI (the rejoin itself is automatic).
      sig.on('status', ({ connected: up }) => setConnected(up))

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
    setRoomScope(scope)
    sig.join(newRoomId, myNameRef.current, uidRef.current)
  }, [])

  const pairWithCode = useCallback(
    (code) => {
      const clean = String(code).trim().toUpperCase()
      if (clean) rejoin(`code-${clean}`, 'code')
    },
    [rejoin],
  )

  const generateCode = useCallback(async () => {
    const { code, room } = await fetch(api('/api/room/code')).then((r) => r.json())
    rejoin(room, 'code')
    return code
  }, [rejoin])

  const useAutoRoom = useCallback(async () => {
    const auto = await fetch(api('/api/room')).then((r) => r.json())
    setNetwork(auto.network)
    rejoin(auto.room, 'auto')
  }, [rejoin])

  // ---- resilience: nudge a reconnect when a suspended tab resumes ----------
  // Mobile browsers freeze background tabs and throttle timers, so socket.io's
  // auto-reconnect can stall. When the page becomes visible again, kick it.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === 'visible') sigRef.current?.reconnect?.()
    }
    document.addEventListener('visibilitychange', onVisible)
    window.addEventListener('focus', onVisible)
    return () => {
      document.removeEventListener('visibilitychange', onVisible)
      window.removeEventListener('focus', onVisible)
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

  const roomCode = useMemo(
    () => (roomId && roomId.startsWith('code-') ? roomId.slice(5) : null),
    [roomId],
  )

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
