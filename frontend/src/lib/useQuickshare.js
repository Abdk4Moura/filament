// useQuickshare — the single hook the UI consumes.
//
// It owns all the networking (config fetch, signaling, a PeerLink per peer) and
// exposes a flat, render-friendly snapshot plus a handful of actions. The shape
// returned here IS the contract documented in CONTRACT.md and handed to Claude
// Design. The visual layer should depend only on this shape — never on the
// socket, the RTCPeerConnection, or anything below.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createSignaling } from './signaling.js'
import { PeerLink } from './webrtc.js'

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

function roomFromUrl() {
  const m = window.location.pathname.match(/^\/rooms\/([^/]+)/)
  return m ? decodeURIComponent(m[1]) : null
}

export function useQuickshare() {
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

  // ---- snapshot helpers (keep React state in sync with the live PeerLinks) --
  const upsertPeer = useCallback((p) => {
    setPeers((prev) => {
      const i = prev.findIndex((x) => x.id === p.id)
      if (i === -1) return [...prev, p]
      const next = [...prev]
      next[i] = { ...next[i], ...p }
      return next
    })
  }, [])

  const removePeer = useCallback((id) => {
    setPeers((prev) => prev.filter((p) => p.id !== id))
  }, [])

  const upsertTransfer = useCallback((t) => {
    transferOwner.current.set(t.id, t.peerId)
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
    ({ id, name, initiator }) => {
      if (linksRef.current.has(id)) return linksRef.current.get(id)
      upsertPeer({ id, name, color: colorFor(id), status: 'connecting', route: null })
      const link = new PeerLink({
        id,
        name,
        iceServers: cfgRef.current.iceServers,
        chunkSize: cfgRef.current.chunkSize,
        initiator,
        sendSignal: (data) => sigRef.current.signal(id, data),
        onStatus: (status) => upsertPeer({ id, status }),
        onTransfer: (t) => upsertTransfer(t),
        onRoute: (route) => upsertPeer({ id, route }),
      })
      linksRef.current.set(id, link)
      return link
    },
    [upsertPeer, upsertTransfer],
  )

  // ---- bootstrap -----------------------------------------------------------
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      const cfg = await fetch('/api/config').then((r) => r.json())
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
        const auto = await fetch('/api/room').then((r) => r.json())
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
        setMe({ id, name: myName, color: colorFor(id) })
        setConnected(true)
        // We are the newcomer: initiate to everyone already here.
        existing.forEach((p) => makeLink({ id: p.id, name: p.name, initiator: true }))
      })
      sig.on('peer-joined', ({ id, name }) => {
        // A newer peer arrived; they initiate to us.
        makeLink({ id, name, initiator: false })
      })
      sig.on('peer-left', ({ id }) => {
        linksRef.current.get(id)?.close()
        linksRef.current.delete(id)
        removePeer(id)
      })
      sig.on('signal', ({ from, data }) => {
        const link =
          linksRef.current.get(from) || makeLink({ id: from, name: from, initiator: false })
        link.accept(data)
      })

      sig.join(room, myName)
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
    sig.join(newRoomId, myNameRef.current)
  }, [])

  const pairWithCode = useCallback(
    (code) => {
      const clean = String(code).trim().toUpperCase()
      if (clean) rejoin(`code-${clean}`, 'code')
    },
    [rejoin],
  )

  const generateCode = useCallback(async () => {
    const { code, room } = await fetch('/api/room/code').then((r) => r.json())
    rejoin(room, 'code')
    return code
  }, [rejoin])

  const useAutoRoom = useCallback(async () => {
    const auto = await fetch('/api/room').then((r) => r.json())
    setNetwork(auto.network)
    rejoin(auto.room, 'auto')
  }, [rejoin])

  // ---- Part C: optional native LAN-discovery helper ------------------------
  // If the Quickshare Local helper (experiments/localsend-discovery) is running,
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
