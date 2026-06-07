// useFilament — the single hook the UI consumes.
//
// It owns all the networking (config fetch, signaling, a PeerLink per peer) and
// exposes a flat, render-friendly snapshot plus a handful of actions. The shape
// returned here IS the contract documented in CONTRACT.md and handed to Claude
// Design. The visual layer should depend only on this shape — never on the
// socket, the RTCPeerConnection, or anything below.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createSignaling } from './signaling.js'
import { createSession } from './session.js'
import { PeerLink, politeRole } from './webrtc.js'
import { api } from './api.js'
import { tel, telPeer, installTel, flush as telFlush } from './tel.js'
import { devicesLoad, devicesStore, devicesForget, channelOf, proofFor } from './devices.js'

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
  const roomIdRef = useRef(null) // current room (mirrors roomId for closures; C30 session owns repair)
  const [roomScope, setRoomScope] = useState(null) // 'auto' | 'code' | 'link' | 'pair'
  const [roomCode, setRoomCode] = useState(null) // the speakable one-time code while waiting
  const [network, setNetwork] = useState(null) // 'ipv4' | 'ipv6' | 'raw'
  const [signalingKind, setSignalingKind] = useState(null)
  const [connected, setConnected] = useState(false)
  const [localHelper, setLocalHelper] = useState({ available: false, peers: [] }) // Part C

  const sigRef = useRef(null)
  const sessionRef = useRef(null) // C30 convergent session — owns the repair loop
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

  // ---- known devices (C12/C20 browser half) ---------------------------------
  // Mutual acknowledgement is structural: presence only lights up when BOTH
  // sides hold the pair secret and raise the same sha256 meeting-point
  // channel. This is the half the browser was missing — it received pair-keep
  // secrets and dropped them, leaving the CLI waving at a rendezvous nobody
  // else knew about (one-sided acknowledgement, observed live 2026-06-07).
  const [knownDevices, setKnownDevices] = useState(() => devicesLoad())
  const channelMapRef = useRef(new Map()) // channel -> {name, secret}
  const expectedSecretRef = useRef(new Map()) // peerId -> {name, secret} (matched via known-peer)
  const digestAbsentRef = useRef(new Map()) // peerId -> consecutive digests it was absent from (C30 ph2)

  /// (Re)derive our known-device channels and hand them to the convergent
  /// session (C30). The session's level-triggered loop owns the repair — the
  /// old C28 belt (acked subscribe + 4s retry ×3 + 1.5s debounce + 45s
  /// reconcile) DISSOLVES into `desired.channels`: every sync re-asserts them
  /// idempotently, so a fresh sid / frozen tab / lost emit self-heals within
  /// one tick. We keep channelMapRef for known-peer matching, and kick() for
  /// the immediate-raise a freshly stored secret needs.
  const subscribeKnown = useCallback(async () => {
    const devs = devicesLoad()
    setKnownDevices(devs)
    try {
      const entries = await Promise.all(devs.map(async (d) => [await channelOf(d.secret), d]))
      channelMapRef.current = new Map(entries)
      sessionRef.current?.setChannels(entries.map(([ch]) => ch))
      sessionRef.current?.kick() // raise immediately; the loop owns the repair
    } catch {
      /* crypto.subtle unavailable (insecure origin) — known devices dormant */
    }
  }, [])

  const forgetDevice = useCallback((name) => {
    setKnownDevices(devicesForget(name))
  }, [])

  // C27: remembering is a TRUST GRANT (the holder can find and auto-connect
  // to this browser forever) — so the human decides, never the protocol.
  // pair-keep offers queue here until answered; the answer goes back as
  // pair-keep-ack so a declined sender discards its half too (a kept-but-
  // unreciprocated secret is exactly the one-sided dead weight C12 cured).
  const [pendingKeeps, setPendingKeeps] = useState([]) // [{peerId, name, secret}]

  const acceptKeep = useCallback((peerId) => {
    setPendingKeeps((prev) => {
      const k = prev.find((x) => x.peerId === peerId)
      if (k) {
        setKnownDevices(devicesStore(k.name, k.secret))
        tel('pair-keep-stored', { peer: peerId.slice(-6) })
        subscribeKnown()
        linksRef.current.get(peerId)?.sendPairKeepAck(true)
      }
      return prev.filter((x) => x.peerId !== peerId)
    })
  }, [subscribeKnown])

  const declineKeep = useCallback((peerId) => {
    setPendingKeeps((prev) => {
      if (prev.some((x) => x.peerId === peerId)) {
        tel('pair-keep-declined', { peer: peerId.slice(-6) })
        linksRef.current.get(peerId)?.sendPairKeepAck(false)
      }
      return prev.filter((x) => x.peerId !== peerId)
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
          // C20: if this peer was introduced via a known-device channel, prove
          // we hold the secret — bound to THIS link's DTLS fingerprints. Both
          // sides do this (mutual acknowledgement), each verifies the other.
          const exp = expectedSecretRef.current.get(id)
          if (exp && uid) {
            const fps = link.fingerprints()
            if (fps) {
              proofFor(exp.secret, uidRef.current, uidRef.current, uid, fps.mine, fps.theirs)
                .then((mac) => {
                  link.sendPairProof(mac)
                  tel('proof-sent', { peer: id.slice(-6) })
                })
                .catch(() => {})
            }
          }
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
        // C12/C27: the peer asked to be remembered. That's a trust grant —
        // queue it for the HUMAN; the banner answers with pair-keep-ack.
        onPairKeep: (secret) => {
          tel('pair-keep-offered', { peer: id.slice(-6) })
          setPendingKeeps((prev) => (prev.some((k) => k.peerId === id) ? prev : [...prev, { peerId: id, name, secret }]))
        },
        // C27: our own remember offer was answered (browser-initiated
        // remembering is Phase B — handled for protocol completeness).
        onPairKeepAck: (ok) => {
          tel(ok ? 'keep-ack-ok' : 'keep-ack-declined', { peer: id.slice(-6) })
        },
        // C20: the peer claims to be a known device — verify against every
        // stored secret, bound to this link's fingerprints. C27: ANSWER
        // either way, so a stale prover learns we never met and stops trying.
        onPairProof: async (mac) => {
          const fps = link.fingerprints()
          const theirUid = link.peerUid
          if (!fps || !theirUid) return tel('proof-unverifiable', { peer: id.slice(-6) })
          for (const d of devicesLoad()) {
            try {
              if ((await proofFor(d.secret, theirUid, theirUid, uidRef.current, fps.mine, fps.theirs)) === mac) {
                updatePeer(id, { verified: d.name })
                link._verified = true // C30 ph3: the link's state ping carries this
                tel('proof-ok', { peer: id.slice(-6) })
                link.sendPairProofAck(true)
                return
              }
            } catch {}
          }
          tel('proof-fail', { peer: id.slice(-6) })
          link.sendPairProofAck(false)
        },
        // C30 ph3: a state ping exposed a one-sided belief on this link.
        onPeerStateDiverged: (kind) => {
          tel('state-diverged', { kind, peer: id.slice(-6) })
          // trust divergence: they don't recognize us but we hold a secret
          // for them — re-prove ONCE per link (webrtc re-offers transfers
          // itself; trust needs the hook, which owns secrets + uids).
          if (kind === 'trust' && !link._reproved) {
            link._reproved = true
            const exp = expectedSecretRef.current.get(id)
            const fps = link.fingerprints()
            if (exp && uid && fps) {
              proofFor(exp.secret, uidRef.current, uidRef.current, uid, fps.mine, fps.theirs)
                .then((mac) => link.sendPairProof(mac))
                .catch(() => {})
            }
          }
        },
        // C27: they answered OUR proof. false = "never met a fella like you"
        // — drop the expectation so we stop claiming acquaintance.
        onPairProofAck: (ok) => {
          if (!ok) {
            expectedSecretRef.current.delete(id)
            updatePeer(id, { verified: null, known: null }) // drop the badge too
            tel('proof-rejected', { peer: id.slice(-6) })
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
    [addPeer, updatePeer, upsertTransfer, removePeer, subscribeKnown],
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

      // C30: the convergent session. Its level-triggered loop owns session-state
      // repair (room membership + channel subscriptions + lease) — replacing the
      // rejoin belt (#14), subscribeKnown's ack-retry/45s-reconcile, and the
      // pair-create lease refresh. The explicit sig.join below stays for instant
      // welcome UX; the loop is the guarantee underneath.
      const session = createSession(sig, tel, (digestPeers) => {
        // C30 phase 2: the server's roster rode in on the sync digest — a
        // missed peer-joined/left self-corrects here. Channel-introduced
        // links are exempt (room-independent); absence must hold for TWO
        // consecutive digests (one can race a join in flight).
        const present = new Set(digestPeers.map((p) => p.id))
        for (const p of digestPeers) {
          if (p.id && !linksRef.current.has(p.id)) {
            tel('digest-adopt', { peer: String(p.id).slice(-6) })
            makeLinkRef.current?.({ id: p.id, name: p.name, uid: p.uid })
          }
        }
        for (const [pid] of [...linksRef.current]) {
          if (expectedSecretRef.current.has(pid)) continue // channel link
          if (present.has(pid)) {
            digestAbsentRef.current.delete(pid)
            continue
          }
          const n = (digestAbsentRef.current.get(pid) || 0) + 1
          digestAbsentRef.current.set(pid, n)
          if (n >= 2) {
            digestAbsentRef.current.delete(pid)
            tel('digest-drop', { peer: pid.slice(-6) })
            linksRef.current.get(pid)?.close()
            linksRef.current.delete(pid)
            removePeer(pid)
            setPendingKeeps((prev) => prev.filter((k) => k.peerId !== pid))
          }
        }
      })
      sessionRef.current = session

      sig.on('welcome', ({ id, peers: existing }) => {
        // Idempotent — also fires on every reconnect AND every room switch
        // (and the rejoin belt adds a second one). Tear down stale ROOM links
        // and rebuild from the fresh roster — but keep channel-introduced
        // known devices: they're in no room roster, so wiping them here made
        // the tile flash in (subscribe → known-peer) and out (next welcome),
        // observed live ("connecting and then gotcha… it disappears").
        myIdRef.current = id // set before makeLink so politeness can be computed (#1)
        for (const [pid, l] of [...linksRef.current]) {
          if (expectedSecretRef.current.has(pid)) continue // known device — room-independent
          l.close()
          linksRef.current.delete(pid)
          removePeer(pid)
        }
        setMe({ id, name: myName, color: colorFor(id) })
        setConnected(true)
        connectedRef.current = true
        existing.forEach((p) => makeLink({ id: p.id, name: p.name, uid: p.uid }))
        subscribeKnown() // re-introduce any known device the wipe-era logic lost
      })
      sig.on('peer-joined', ({ id, name, uid }) => {
        makeLink({ id, name, uid })
      })
      sig.on('peer-left', ({ id }) => {
        linksRef.current.get(id)?.close()
        linksRef.current.delete(id)
        removePeer(id)
        setPendingKeeps((prev) => prev.filter((k) => k.peerId !== id)) // moot now (C27)
      })
      // C12: a known device came online (matched one of our secret-derived
      // channels) — link to it regardless of rooms. Both sides receive this;
      // the polite/impolite roles sort out who offers.
      sig.on('known-peer', ({ id, name, uid, channel }) => {
        if (!id || uid === uidRef.current) return // our own other session
        const dev = channelMapRef.current.get(channel)
        if (!dev) return
        expectedSecretRef.current.set(id, dev)
        tel('known-peer', { peer: id.slice(-6) })
        if (!linksRef.current.has(id)) makeLink({ id, name: name || dev.name, uid })
        // Mark the tile as a remembered device — the UI renders it distinctly
        // (room-independent: it's here because of the pairing, not the room).
        updatePeer(id, { known: dev.name })
      })
      sig.on('known-peer-left', ({ id }) => {
        expectedSecretRef.current.delete(id)
        const l = linksRef.current.get(id)
        if (l) {
          l.close()
          linksRef.current.delete(id)
          removePeer(id)
        }
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
          // C30: a reconnect gives us a fresh sid that the server dropped from
          // its room + subscriptions (#14 roomless ghost; C12 lost channels).
          // The convergent session re-ensures BOTH on socket-up — room and
          // channels are both in `desired`, one idempotent sync repairs them.
          // No bespoke rejoin belt, no separate re-subscribe. invalidate()
          // first: the fresh sid voids the last confirmation, so the kick emits
          // even inside the 30s staleness window (else: roomless-ghost lag).
          session.invalidate()
          session.kick()
        }
      })

      // Seed the convergent session with our room, then fire the initial join
      // for instant welcome UX. From here the session loop owns the repair.
      session.setRoom(room, myName, uidRef.current)
      sig.join(room, myName, uidRef.current)
      session.kick() // independent of subscribeKnown (which no-ops with 0 devices)
      subscribeKnown()
    })()
    return () => {
      cancelled = true
      sessionRef.current?.stop() // clear the 5s loop (HMR/unmount leak otherwise)
      sigRef.current?.leave()
      linksRef.current.forEach((l) => l.close())
      linksRef.current.clear()
    }
  }, [makeLink, removePeer, subscribeKnown])

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
    // C30: update the convergent session's desired room BEFORE the join, else
    // the next 5s sync re-asserts the OLD room and the server moves us back.
    // setRoom + kick = the deliberate switch; the loop then keeps it.
    sessionRef.current?.setRoom(newRoomId, myNameRef.current, uidRef.current)
    sig.join(newRoomId, myNameRef.current, uidRef.current)
    sessionRef.current?.kick()
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
        sessionRef.current?.kick() // C30: re-ensure room + channels the freeze may have eaten
        subscribeKnown() // re-derive channels in case a secret was stored while hidden
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
  }, [subscribeKnown])

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
    knownDevices, // C12: [{name, secret, addedAt}] — remembered devices
    forgetDevice, // C12: drop a remembered device by name
    pendingKeeps, // C27: [{peerId, name}] — peers asking to be remembered
    acceptKeep, // C27: store the secret + ack; auto-connect from now on
    declineKeep, // C27: refuse; the sender discards its half too
  }
}
