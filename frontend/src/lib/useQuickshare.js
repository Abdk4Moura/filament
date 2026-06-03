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
  const [signalingKind, setSignalingKind] = useState(null)
  const [connected, setConnected] = useState(false)

  const sigRef = useRef(null)
  const linksRef = useRef(new Map()) // peerId -> PeerLink
  const transferOwner = useRef(new Map()) // transferId -> peerId
  const cfgRef = useRef(null)

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
      upsertPeer({ id, name, color: colorFor(id), status: 'connecting' })
      const link = new PeerLink({
        id,
        name,
        iceServers: cfgRef.current.iceServers,
        chunkSize: cfgRef.current.chunkSize,
        initiator,
        sendSignal: (data) => sigRef.current.signal(id, data),
        onStatus: (status) => upsertPeer({ id, status }),
        onTransfer: (t) => upsertTransfer(t),
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

      const room = roomFromUrl() || (await fetch('/api/room').then((r) => r.json())).room
      if (cancelled) return
      setRoomId(room)

      const sig = await createSignaling(cfg)
      sigRef.current = sig
      const myName = randomName()

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
    signalingKind,
    connected,
    sendFiles,
    acceptTransfer,
    declineTransfer,
    saveTransfer,
    clearTransfer,
  }
}
