// useFilament: the single hook the UI consumes.
//
// It owns all the networking (config fetch, signaling, a PeerLink per peer) and
// exposes a flat, render-friendly snapshot plus a handful of actions. The shape
// returned here IS the contract documented in CONTRACT.md and handed to Claude
// Design. The visual layer should depend only on this shape, never on the
// socket, the RTCPeerConnection, or anything below.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createSignaling } from './signaling.js'
import { createSession } from './session.js'
import { PeerLink, politeRole } from './webrtc.js'
import { api } from './api.js'
import { tel, telPeer, installTel, flush as telFlush } from './tel.js'
import * as linkdiag from './linkdiag.js'
import { log } from './log.js'
import { devicesLoad, devicesStore, devicesStoreV2, devicesForget, devicesRename, channelOf, proofFor } from './devices.js'
import { mintWords, mintNameplate, ADJ, ANIMAL as ANIMALS } from './words.js'
import { pakeReady, PakePairing, parseSpokenCode, splitChosenCode, PAIR_V2_CAPS } from './pairing.js'

// Peer display names draw from the same 64x64 vocabulary as the pairing
// wordlists, imported from words.js (ADJ/ANIMAL) so there is a single source
// of truth (was duplicated here). 4,096 combinations picked via
// crypto.getRandomValues, persisted per tab: a device KEEPS its name on purpose
// (stable identity, like the uid below): recurrence across visits is
// sessionStorage, not a small or biased RNG. See the variance analysis repo for
// the entropy/birthday math.

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
  const sessionRef = useRef(null) // C30 convergent session, owns the repair loop
  // Live socket truth for non-render code paths (state in closures goes
  // stale). Set everywhere setConnected is.
  const connectedRef = useRef(false)
  const linksRef = useRef(new Map()) // peerId -> PeerLink
  const transferOwner = useRef(new Map()) // transferId -> peerId
  const cfgRef = useRef(null)
  const myNameRef = useRef(null)
  const myIdRef = useRef(null) // our current socket id, for the politeness tiebreaker (#1)
  const uidRef = useRef(tabUid()) // stable per-tab identity (resume)
  // Resume stores, deliberately OUTLIVE individual PeerLinks (see docs/resilience.md):
  const partialsRef = useRef(new Map()) // transferId -> { received, buffers, size, mime, name }
  const outgoingRef = useRef(new Map()) // transferId -> { file, name, size, mime, peerUid }
  const transferStatusRef = useRef(new Map()) // transferId -> latest status
  const attemptsRef = useRef(new Map()) // peerId -> watchdog retry count (#8)
  const relayedRef = useRef(new Map()) // peerId -> relay-preferred rebuild count (P1: at-most-once escalation)
  const makeLinkRef = useRef(null) // lets onStuck re-create a link without closure cycles
  const prevScopeRef = useRef('auto') // restore the discovery bar after a code is used

  // ---- snapshot helpers (keep React state in sync with the live PeerLinks) --
  const addPeer = useCallback((p) => {
    setPeers((prev) => (prev.some((x) => x.id === p.id) ? prev : [...prev, p]))
  }, [])

  // Update an EXISTING peer only, never re-adds (#3). A late callback from a
  // closed PeerLink must not resurrect a tile we already removed.
  const updatePeer = useCallback((id, patch) => {
    if (patch.status) {
      telPeer(id, patch.status)
      // info = the value-prop moment a peer becomes usable; failures are warn.
      if (patch.status === 'ready') log.info('peer ready', id.slice(-6))
      else if (patch.status === 'failed') log.warn('peer failed', id.slice(-6))
      else log.debug('peer status', id.slice(-6), patch.status)
    }
    if (patch.route) {
      tel('peer-route', { peer: id.slice(-6), route: patch.route })
      // route change direct<->relay is the firehose's debug tier; the value
      // proposition itself stays in the UI (route badge / amber relay chip).
      log.debug('route', id.slice(-6), patch.route)
    }
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
    if (t.status && transferStatusRef.current.get(t.id) !== t.status) {
      // info = transfer reached a terminal/usable state; transferring chatter
      // and progress are trace.
      if (t.status === 'complete') log.info('transfer complete', t.id, t.name || '')
      else if (t.status === 'failed' || t.status === 'declined') log.debug('transfer ' + t.status, t.id)
      else log.trace('transfer', t.id, t.status)
    }
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
  // channel. This is the half the browser was missing: it received pair-keep
  // secrets and dropped them, leaving the CLI waving at a rendezvous nobody
  // else knew about (one-sided acknowledgement, observed live 2026-06-07).
  const [knownDevices, setKnownDevices] = useState(() => devicesLoad())
  const channelMapRef = useRef(new Map()) // channel -> {name, secret}
  const expectedSecretRef = useRef(new Map()) // peerId -> {name, secret} (matched via known-peer)
  const digestAbsentRef = useRef(new Map()) // peerId -> consecutive digests it was absent from (C30 ph2)

  /// (Re)derive our known-device channels and hand them to the convergent
  /// session (C30). The session's level-triggered loop owns the repair: the
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
      /* crypto.subtle unavailable (insecure origin): known devices dormant */
    }
  }, [])

  const forgetDevice = useCallback((name) => {
    setKnownDevices(devicesForget(name))
  }, [])

  // Rename a remembered device's LOCAL petname (no backend, no wire). The secret
  // is unchanged, so the meeting-point channel and every proof stay byte-stable,
  // this is purely the human-facing label. We (1) persist via devicesRename,
  // (2) re-derive channels so channelMapRef/expectedSecretRef carry the new name
  // (their `dev.name` is what lights up a tile's `known`), and (3) patch any live
  // tile whose `known`/`verified` still shows the old label so it updates at once.
  const renameDevice = useCallback((oldName, newName) => {
    const next = String(newName || '').trim()
    if (!next || next === oldName) return
    setKnownDevices(devicesRename(oldName, next))
    for (const [pid, dev] of expectedSecretRef.current) {
      if (dev?.name === oldName) expectedSecretRef.current.set(pid, { ...dev, name: next })
    }
    subscribeKnown() // re-key channelMapRef → new dev.name
    setPeers((prev) =>
      prev.map((p) => ({
        ...p,
        ...(p.known === oldName ? { known: next } : null),
        ...(p.verified === oldName ? { verified: next } : null),
      })),
    )
  }, [subscribeKnown])

  // C27: remembering is a TRUST GRANT (the holder can find and auto-connect
  // to this browser forever), so the human decides, never the protocol.
  // pair-keep offers queue here until answered; the answer goes back as
  // pair-keep-ack so a declined sender discards its half too (a kept-but-
  // unreciprocated secret is exactly the one-sided dead weight C12 cured).
  const [pendingKeeps, setPendingKeeps] = useState([]) // [{peerId, name, secret}]

  // ---- L1-a PAKE v2 pairing state -----------------------------------------
  // The pending v2 pairing config (nameplate + locally-held password) set when
  // we create/claim a code; consumed once we land in the paired room and a link
  // comes up. The active PakePairing runs SPAKE2 over the `signal` relay.
  const pakeReadyRef = useRef(false)
  const pendingPakeRef = useRef(null) // { nameplate, password } awaiting a peer
  const pakeRef = useRef(null) // active PakePairing for the current peer
  const pakePeerRef = useRef(null) // peer sid we run the PAKE with
  // L1-a: peers authenticated by an EPHEMERAL transfer-auth ceremony
  // (receiveWithCode), secret discarded, link trusted only for this session's
  // incoming transfer. Distinct from a remembered (stored) device.
  const ephemeralAuthRef = useRef(new Set())
  const [pairStatus, setPairStatus] = useState(null) // 'pairing' | 'paired' | 'refused' | error string
  // L1-a consent (mirrors C27 pendingKeeps for v2): when a PAKE completes, K is
  // agreed but remembering is a separate TRUST GRANT the human decides. Queue
  // {peerId, name, secret, caps} here and prompt before any local store.
  const [pendingPakeKeep, setPendingPakeKeep] = useState([]) // [{peerId, name, secret, caps}]
  // Drive the active pairing one step (idempotent): send our element, then the
  // confirm once K + fingerprints exist; finalize on success/abort.
  const drivePakeRef = useRef(() => {})

  // L1-a: the human chose to remember this v2-paired device. v2 keeps are
  // LOCAL-ONLY: both sides hold K independently, so there's no wire ack and no
  // half to discard (unlike v1's sendPairKeepAck). Store under the chosen name.
  const acceptPakeKeep = useCallback((peerId, chosenName) => {
    setPendingPakeKeep((prev) => {
      const k = prev.find((x) => x.peerId === peerId)
      if (k) {
        const name = (chosenName && String(chosenName).trim()) || k.name
        setKnownDevices(devicesStoreV2(name, k.secret, k.caps))
        tel('pake-paired-stored', { peer: String(peerId).slice(-6) })
        subscribeKnown()
      }
      return prev.filter((x) => x.peerId !== peerId)
    })
  }, [subscribeKnown])

  // L1-a: declined remembering. K stays agreed (fine, the device just isn't
  // remembered); nothing to undo locally, just drop the prompt.
  const declinePakeKeep = useCallback((peerId) => {
    setPendingPakeKeep((prev) => {
      if (prev.some((x) => x.peerId === peerId)) tel('pake-keep-declined', { peer: String(peerId).slice(-6) })
      return prev.filter((x) => x.peerId !== peerId)
    })
  }, [])

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
    ({ id, name, uid, relayOnly }) => {
      if (linksRef.current.has(id)) return linksRef.current.get(id)
      // Supersede (#10): a tab has exactly ONE live connection. If we already
      // show a tile for this uid under an older sid (zombie registry entry, or
      // peer-joined arriving before peer-left during a reconnect), replace it,
      // never show the same device twice.
      if (uid) {
        for (const [oldId, oldLink] of [...linksRef.current]) {
          if (oldId !== id && oldLink.peerUid === uid) {
            linksRef.current.delete(oldId)
            oldLink.close()
            removePeer(oldId)
            attemptsRef.current.delete(oldId)
            relayedRef.current.delete(oldId)
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
        // P1 (GAP-4): force this link's ICE through the TURN relay when we're
        // rebuilding after a persistent stall (see onStall below).
        relayOnly: !!relayOnly,
        chunkSize: cfgRef.current.chunkSize,
        polite,
        peerUid: uid || null,
        stores: { partials: partialsRef.current, outgoing: outgoingRef.current },
        sendSignal: (data) => sigRef.current.signal(id, data),
        onStatus: (status) => updatePeer(id, { status }),
        onTransfer: (t) => upsertTransfer(t),
        onRoute: (route) => updatePeer(id, { route }),
        // web-shell: the peer announced whether it offers a terminal, surfaces
        // the per-device shell button only for shell-enabled devices.
        onCaps: (caps) => updatePeer(id, { shell: !!caps.shell }),
        // Resume: once the channel is open, re-offer any paused sends that were
        // headed to this same device (matched by its stable uid).
        onChannelOpen: () => {
          attemptsRef.current.delete(id) // established, reset watchdog retries
          // L1-a: a v2 pairing is in flight for this peer; now that SDP (and
          // thus the DTLS fingerprints) is exchanged, run the SPAKE2 ceremony.
          if (pendingPakeRef.current) {
            ensurePakePairing(id)
            drivePake()
          }
          // C20: if this peer was introduced via a known-device channel, prove
          // we hold the secret, bound to THIS link's DTLS fingerprints. Both
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
            // both must re-offer on the fresh channel.
            const st = transferStatusRef.current.get(tid)
            if (entry.peerUid === uid && (st === 'paused' || st === 'offered')) {
              link.resumeSend(tid)
            }
          }
        },
        // C12/C27: the peer asked to be remembered. That's a trust grant,
        // queue it for the HUMAN; the banner answers with pair-keep-ack.
        // L1-a downgrade-refusal (spec §6.1): if WE are mid v2 pairing, a
        // pair-keep means the peer is a legacy v1 client. Refuse: secure
        // first-pairing requires v2 on both ends. We NEVER store a
        // server-readable secret on the v2 path, so a server stripping v:2
        // cannot force this downgrade.
        onPairKeep: (secret) => {
          if (pendingPakeRef.current) {
            tel('pake-refuse-v1-peer', { peer: id.slice(-6) })
            setPairStatus('the other device uses an older version and cannot pair securely. Update it. Nothing was stored.')
            link.sendPairKeepAck(false)
            return
          }
          tel('pair-keep-offered', { peer: id.slice(-6) })
          setPendingKeeps((prev) => (prev.some((k) => k.peerId === id) ? prev : [...prev, { peerId: id, name, secret }]))
        },
        // C27: our own remember offer was answered (browser-initiated
        // remembering is Phase B, handled for protocol completeness).
        onPairKeepAck: (ok) => {
          tel(ok ? 'keep-ack-ok' : 'keep-ack-declined', { peer: id.slice(-6) })
        },
        // C20: the peer claims to be a known device: verify against every
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
          // for them, re-prove ONCE per link (webrtc re-offers transfers
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
        // drop the expectation so we stop claiming acquaintance.
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
        // P1 (GAP-4): the in-flight stall ladder (P0 rungs a+b) is exhausted on
        // this link, a chronically stalled direct/STUN path. Rebuild the link
        // RELAY-PREFERRED (iceTransportPolicy:'relay'), mirroring the Rust
        // client's auto-relay at ladder exhaustion. The amber RELAY UI lights
        // itself via the normal _detectRoute()→onRoute('relayed') path; the
        // hook-owned partials/outgoing stores outlive the link, so the re-offer
        // -on-channel-open path RESUMES the in-flight transfer (not restart).
        // Bounded: a peer is escalated to relay at most ONCE; a relay link that
        // itself stalls falls through to P0's terminal _failActive, never an
        // infinite relay-rebuild loop.
        onStall: ({ reason }) => {
          if (reason !== 'persistent') return
          if (relayOnly) {
            // We're already on the relay and it stalled too, don't re-escalate.
            // Let P0's terminal _failActive own it (partials preserved).
            log.debug('rtc: relay link still stalled, leaving terminal failure to P0', id.slice(-6))
            return
          }
          const r = relayedRef.current.get(id) || 0
          if (r >= 1) {
            log.debug('rtc: persistent stall but relay-preferred already spent, not re-escalating', id.slice(-6))
            return
          }
          relayedRef.current.set(id, r + 1)
          log.info('rtc: persistent stall, rebuilding relay-preferred (auto-relay fallback)', id.slice(-6))
          linksRef.current.delete(id)
          link.close()
          makeLinkRef.current?.({ id, name, uid, relayOnly: true })
        },
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
            // finally fails, grant ONE delayed fresh start, covers the
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
      // Link-diagnostics: a makeLink is a (re)build; relayOnly marks the P1
      // relay-preferred rebuild. Tagged with the peer uid so the timeline shows
      // exactly when a fresh link replaced a dead one.
      linkdiag.record('makeLink', { relayOnly: !!relayOnly, polite }, { uid: uid || id })
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
      linkdiag.installEnv() // link-diagnostics: env/network taps (vis, online, conn, pagehide)
      const myName = randomName()
      myNameRef.current = myName

      // C30: the convergent session. Its level-triggered loop owns session-state
      // repair (room membership + channel subscriptions + lease), replacing the
      // rejoin belt (#14), subscribeKnown's ack-retry/45s-reconcile, and the
      // pair-create lease refresh. The explicit sig.join below stays for instant
      // welcome UX; the loop is the guarantee underneath.
      const session = createSession(sig, tel, (digestPeers) => {
        // C30 phase 2: the server's roster rode in on the sync digest, a
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
        // Idempotent: also fires on every reconnect AND every room switch
        // (and the rejoin belt adds a second one). Tear down stale ROOM links
        // and rebuild from the fresh roster, but keep channel-introduced
        // known devices: they're in no room roster, so wiping them here made
        // the tile flash in (subscribe → known-peer) and out (next welcome),
        // observed live ("connecting and then gotcha… it disappears").
        myIdRef.current = id // set before makeLink so politeness can be computed (#1)
        for (const [pid, l] of [...linksRef.current]) {
          if (expectedSecretRef.current.has(pid)) continue // known device, room-independent
          // G-i: a signaling reconnect (our OWN socket blipped, welcome
          // re-fires) must NOT tear down a HEALTHY P2P link. The data channel
          // is peer-to-peer and independent of the signaling socket; nuking it
          // here interrupts an in-flight transfer for no reason (the gate-6
          // browser-churn flake; and any user's WiFi blip mid-send). Keep a
          // connected link; only rebuild dead ones. (The remote's sid is the
          // map key and is unaffected by OUR reconnect, so no re-key needed.)
          if (l.pc?.connectionState === 'connected') continue
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
      // channels): link to it regardless of rooms. Both sides receive this;
      // the polite/impolite roles sort out who offers.
      sig.on('known-peer', ({ id, name, uid, channel }) => {
        if (!id || uid === uidRef.current) return // our own other session
        const dev = channelMapRef.current.get(channel)
        if (!dev) return
        expectedSecretRef.current.set(id, dev)
        tel('known-peer', { peer: id.slice(-6) })
        if (!linksRef.current.has(id)) makeLink({ id, name: name || dev.name, uid })
        // Mark the tile as a remembered device: the UI renders it distinctly
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
        // L1-a: PAKE messages ride the opaque `signal` relay. If we have a
        // pending v2 pairing, route pake-msg/pake-confirm into the PAKE machine
        // (creating the PakePairing on first contact), OUT of the WebRTC path.
        if (data?.type === 'pake-msg' || data?.type === 'pake-confirm') {
          ensurePakePairing(from)
          if (pakeRef.current && pakePeerRef.current === from) {
            pakeRef.current.onSignal(data)
            drivePake()
          }
          return
        }
        let link = linksRef.current.get(from)
        if (!link) {
          // Only an incoming offer may create a new link; ignore stray answers/
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
      // party; the code is burned; move both into the private room.
      sig.on('pair-matched', ({ room }) => {
        log.debug('pair matched, joining room')
        setRoomCode(null)
        rejoinRef.current?.(room, 'pair')
      })
      sig.on('pair-used', () => {
        // Our code was claimed: the new person is joining OUR room (we never
        // moved). Clear the code; mint another to add another person.
        setRoomCode(null)
        setRoomScope((s) => (s === 'code' ? prevScopeRef.current || 'auto' : s))
      })
      sig.on('pair-error', ({ error, why }) => {
        log.warn('pairing failed:', error, why || '')
        // Only translate CLAIM failures (we typed a code) into user-facing
        // status. A create-side collision ('taken') is handled by generateCode's
        // own retry and must not flash an error here.
        if (error === 'invalid') {
          if (why === 'bad-nameplate') {
            setPairStatus('that code is not valid. Check it and re-enter it (a full code looks like brave-otter-ruby-3141)')
          } else if (why === 'sender-gone') {
            setPairStatus('the other device left before you paired. Ask them to create a fresh code, then try again')
          } else {
            // 'unknown': never existed / expired / already used.
            setPairStatus('that code did not work. It may be mistyped, expired, or already used. Ask for a fresh code and try again.')
          }
        } else if (error === 'slow-down') {
          setPairStatus('too many attempts. Wait a moment and try again')
        }
        setRoomCode(null)
        setRoomScope((s) => (s === 'code' ? prevScopeRef.current || 'auto' : s))
      })

      // Reflect transport up/down in the UI (the rejoin itself is automatic),
      // and refresh ICE config on reconnect (TURN creds are time-limited, #9).
      sig.on('status', ({ connected: up }) => {
        tel(up ? 'socket-up' : 'socket-down', {})
        linkdiag.record('signal', { state: up ? 'connect' : 'disconnect' }) // signaling status change

        // info = socket connected (a lifecycle landmark); a drop is debug,
        // the rejoin is automatic, so it's not a user-actionable warning.
        if (up) log.info('socket connected')
        else log.debug('socket disconnected (auto-reconnecting)')
        if (!up) telFlush()
        setConnected(up)
        connectedRef.current = up
        if (up) {
          fetch(api('/api/config')).then((r) => r.json()).then((c) => { cfgRef.current = c }).catch(() => {})
          // C30: a reconnect gives us a fresh sid that the server dropped from
          // its room + subscriptions (#14 roomless ghost; C12 lost channels).
          // The convergent session re-ensures BOTH on socket-up: room and
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

  // L1-a: finalize a completed PakePairing, store the device under K-derived
  // secret with its agreed caps, or surface the refusal. Idempotent.
  const finalizePake = useCallback(() => {
    const p = pakeRef.current
    if (!p) return
    if (p.secret) {
      const peerId = pakePeerRef.current
      const name = (peerId && linksRef.current.get(peerId)?.name) || 'device'
      // L1-a EPHEMERAL transfer-auth (receiveWithCode): the SAME ceremony runs,
      // but the agreed secret is DISCARDED, it only authenticated the link
      // (mutual auth, MITM-detectable). NO device is remembered. The peer is now
      // trusted for THIS session's incoming transfer; mark the link verified so
      // the existing transfer UI treats it as an authenticated sender.
      if (pendingPakeRef.current?.ephemeral) {
        if (peerId) {
          const link = linksRef.current.get(peerId)
          if (link) link._verified = true
          updatePeer(peerId, { verified: name })
          ephemeralAuthRef.current.add(peerId)
        }
        tel('pake-transfer-authed', { peer: String(peerId).slice(-6) })
        setPairStatus('connected') // authenticated; ready to receive (secret discarded)
        pakeRef.current = null
        pendingPakeRef.current = null
        return
      }
      // K is agreed, pairing crypto succeeded. But remembering is a separate
      // trust grant (C27): queue a consent prompt instead of storing silently.
      // Capture secret/caps/name NOW, before we null pakeRef below. Dedup by
      // peerId so the per-tick drivePake doesn't enqueue twice.
      setPendingPakeKeep((prev) => (prev.some((k) => k.peerId === peerId) ? prev : [...prev, { peerId, name, secret: p.secret, caps: p.caps }]))
      tel('pake-paired', { peer: String(peerId).slice(-6) })
      setPairStatus('paired')
      pakeRef.current = null
      pendingPakeRef.current = null
    } else if (p.aborted) {
      tel('pake-refused', { why: p.aborted })
      setPairStatus(`pairing refused: ${p.aborted}`)
      pakeRef.current = null
      pendingPakeRef.current = null
    }
  }, [subscribeKnown])

  // L1-a: lazily create the PakePairing for `peerId` from the pending config
  // (set by generateCode/pairWithCode). Binds the SPAKE2 session to THIS peer.
  const ensurePakePairing = useCallback((peerId) => {
    if (pakeRef.current && pakePeerRef.current === peerId) return pakeRef.current
    const cfg = pendingPakeRef.current
    if (!cfg || !pakeReadyRef.current) return null
    pakePeerRef.current = peerId
    pakeRef.current = new PakePairing({
      nameplate: cfg.nameplate,
      password: cfg.password,
      caps: PAIR_V2_CAPS,
      sendSignal: (payload) => sigRef.current?.signal(peerId, payload),
      getFingerprints: () => linksRef.current.get(peerId)?.fingerprints() || null,
    })
    setPairStatus('pairing')
    return pakeRef.current
  }, [])

  // L1-a: drive the active pairing one step (idempotent). Called when a link
  // comes up, on each inbound PAKE signal, and from a short poll for the
  // fingerprint-dependent confirm step.
  const drivePake = useCallback(() => {
    const p = pakeRef.current
    if (!p) return
    if (!p.aborted && !p.secret) {
      p.sendOurMessage()
      p.tryConfirm()
    }
    finalizePake()
  }, [finalizePake])
  drivePakeRef.current = drivePake

  const pairWithCode = useCallback(async (code) => {
    const clean = String(code).trim()
    if (!clean) return
    // L1-a (PAKE v2): parse the typed code CLIENT-SIDE; send ONLY the nameplate
    // to the server. The password (words) feeds SPAKE2 and never leaves here.
    setPairStatus(null) // clear any stale failure from a previous attempt
    await pakeReady()
    pakeReadyRef.current = true
    // Parse with the SHARED WASM normCode/splitCode (via parseSpokenCode) so the
    // browser's view of {nameplate, password} is byte-identical to the CLI's:
    // SPAKE2 hashes exactly this `password`, so any drift between an inline
    // validator and the real split would silently break key agreement. A valid
    // PAKE code is `words…-NNNN`: a numeric trailing nameplate (3-5 digits,
    // matching the server's _NAMEPLATE_RE) AND at least one word of password
    // before it. The error cases below are derived from the shared split, not a
    // separate regex, keeping a clear case-specific message.
    const { nameplate, password } = parseSpokenCode(clean)
    const numericNameplate = /^[0-9]{3,5}$/.test(nameplate)
    if (!numericNameplate) {
      // The shared split's trailing group isn't a numeric nameplate (no number
      // at all, or a partial/typo'd code): there is nothing for the server to
      // route on.
      setPairStatus('that code is missing its number. A full code ends in a 3-5 digit number, e.g. brave-otter-3141')
      return
    }
    if (!password) {
      // A bare number with no words before it: nothing for SPAKE2 to hash.
      setPairStatus('that does not look like a full code. Type the whole thing, e.g. brave-otter-3141')
      return
    }
    pendingPakeRef.current = { nameplate, password }
    setPairStatus('pairing')
    sigRef.current?.pairClaimV2(nameplate)
  }, [])

  // L1-a: RECEIVE WITH CODE, claim a transfer code, run the SAME ephemeral
  // SPAKE2 ceremony as pairWithCode, but DISCARD the agreed secret (it only
  // authenticates the link; no device is remembered). After the ceremony
  // confirms, the existing transfer machinery (PeerLink file-offer → onTransfer
  // → acceptTransfer → file-data → file-end → delivery-ack) delivers the file.
  // Sibling to pairWithCode: the ONLY difference is `ephemeral:true`, which
  // makes finalizePake discard rather than queue a remember-consent.
  const receiveWithCode = useCallback(async (code) => {
    const clean = String(code).trim()
    if (!clean) return
    setPairStatus(null)
    await pakeReady()
    pakeReadyRef.current = true
    // Parse with the SHARED WASM normCode/splitCode so {nameplate, password} is
    // byte-identical to the CLI sender, SPAKE2 hashes exactly this password.
    const { nameplate, password } = parseSpokenCode(clean)
    const numericNameplate = /^[0-9]{3,5}$/.test(nameplate)
    if (!numericNameplate) {
      setPairStatus('that code is missing its number, a full code ends in a 3-5 digit number, e.g. brave-otter-3141')
      return
    }
    if (!password) {
      setPairStatus('that does not look like a full code, type the whole thing, e.g. brave-otter-3141')
      return
    }
    // `ephemeral:true` is the only difference from pairWithCode: the agreed
    // secret authenticates this transfer and is then discarded (never stored).
    pendingPakeRef.current = { nameplate, password, ephemeral: true }
    setPairStatus('pairing')
    sigRef.current?.pairClaimV2(nameplate)
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
    // after hiding and takes ~4.3s to recover after refocus, exactly when
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
    // L1-a (PAKE v2): mint the WORDS locally; the server allocates ONLY the
    // numeric nameplate. The full code is assembled+displayed from our OWN mint
    // when pair-ok arrives (the server never echoes any words).
    try {
      await pakeReady()
    } catch (e) {
      // The secure-pairing WASM failed to load (e.g. the asset 404'd and the SPA
      // fallback served HTML). Surface it instead of hanging on a click.
      log.debug('pakeReady failed', { err: String(e) })
      setPairStatus("couldn't load the secure-pairing module. Reload the page and try again.")
      return null
    }
    pakeReadyRef.current = true
    // STEERING: a custom string the user typed ("choose your own"). Parse it with
    // the SHARED split (normCode/splitCode via parseSpokenCode) so the words feed
    // SPAKE2 byte-identically; the words are the password, the trailing number (if
    // any) is the user's chosen nameplate. Any number the user supplied is honored
    // ONCE; on collision we auto-pick a fresh nameplate (the number is never
    // load-bearing for the secret). If they supplied no number we always mint one.
    // Use the chosen-code split (trailing group is the nameplate ONLY if numeric;
    // otherwise it's part of the words) so `gigantic-element` keeps both words.
    const custom = kw ? splitChosenCode(kw) : null
    const customPassword = custom && /[a-z]{2,}/.test(custom.password) ? custom.password : null
    let chosenNameplate = custom && /^[0-9]{3,5}$/.test(custom.nameplate) ? custom.nameplate : null
    return new Promise((resolve) => {
      let retried = false
      let settled = false
      let watchdog
      const mintAndCreate = () => {
        // Words: the user's chosen password, else a fresh mint. Nameplate: the
        // user's chosen one (first try) else a fresh mint; subsequent retries
        // always mint fresh (the chosen one collided / timed out).
        const words = customPassword || mintWords()
        const nameplate = chosenNameplate || mintNameplate()
        chosenNameplate = null // honor a user-chosen number only on the FIRST try
        const full = `${words}-${nameplate}`
        // Stash the password so the eventual peer can run SPAKE2 with us.
        pendingPakeRef.current = { nameplate, password: words, full, askedNameplate: custom?.nameplate || null }
        sig.pairCreateV2(nameplate)
        return full
      }
      // These handlers used to be added on EVERY click and never removed (the
      // Emitter only had on()), so a later pair-error/-code fired every stale
      // handler. off() + the `settled` guard keep each create attempt isolated.
      const cleanup = () => {
        clearTimeout(watchdog)
        sig.off?.('pair-error', onError)
        sig.off?.('pair-ok', onOk)
        sig.off?.('pair-code', onDowngrade)
      }
      const finish = (val) => {
        if (settled) return
        settled = true
        cleanup()
        resolve(val)
      }
      const arm = () =>
        setTimeout(() => {
          if (!retried) {
            retried = true
            tel('pair-create-retry', { afterMs: Date.now() - t0 })
            sig.reconnect?.()
            waitUp(6000).then(() => {
              watchdog = arm()
              mintAndCreate()
            })
          } else {
            tel('pair-create-timeout', { afterMs: Date.now() - t0 })
            telFlush()
            setPairStatus("the server isn't responding. Check your connection and try again.")
            finish(null)
          }
        }, 5000)
      // Collision: the server says our nameplate is taken, re-mint and retry.
      // If the user had CHOSEN that number, tell them which fresh one we used.
      function onError({ error }) {
        if (error !== 'taken') return
        const asked = pendingPakeRef.current?.askedNameplate
        mintAndCreate()
        const used = pendingPakeRef.current?.nameplate
        if (asked && used && asked !== used) {
          setPairStatus(`that number (${asked}) was busy, we used ${used}`)
        }
      }
      // DOWNGRADE GUARD: a v1-only / out-of-date server answers our v2
      // pair-create with `pair-code` (it minted the whole code) instead of
      // `pair-ok`. We can't pair securely against it, say so loudly instead of
      // waiting forever (this was the silent "create code does nothing" against
      // a stale backend).
      function onDowngrade() {
        tel('pair-create-downgrade', { afterMs: Date.now() - t0 })
        setPairStatus("this server is out of date. It can't create a secure code yet. Try again shortly.")
        finish(null)
      }
      function onOk() {
        const full = pendingPakeRef.current?.full
        tel('pair-create-ok', { rttMs: Date.now() - t0, retried, v: 2 })
        log.debug('pair code ready', { rttMs: Date.now() - t0, retried })
        setRoomCode(full)
        setPairStatus('pairing')
        setRoomScope((s) => {
          if (s !== 'code') prevScopeRef.current = s
          return 'code'
        })
        finish(full)
      }
      watchdog = arm()
      sig.on('pair-error', onError)
      sig.on('pair-ok', onOk)
      sig.on('pair-code', onDowngrade)
      mintAndCreate()
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
  // C21 (brb): going hidden (opening a file picker hides the tab on mobile)
  // tells every connected peer we'll be right back, so they hold the line for
  // the declared window instead of guessing; coming back says so.
  useEffect(() => {
    // P5: a network change is the strongest "a new direct path may exist NOW"
    // signal we can read in a browser (the analog of the Rust client's iface-
    // change re-probe). Nudge every relayed link to re-probe immediately so a
    // wifi/cellular handoff upgrades off relay at once instead of waiting out the
    // backed-off cadence. Covers refocus, `online`, and Network Information API.
    const nudgeUpgradeProbes = () => {
      for (const link of linksRef.current.values()) link.probeUpgradeNow?.()
    }
    // M3/M4: the shared RECOVERY body, extracted from the visibilitychange handler
    // so the SAME repair runs on every "we may be on a new network now" trigger:
    // refocus (visibility/focus), `online`, navigator.connection 'change' (a
    // wifi<->cellular handoff), and a BFCache restore (pageshow persisted). It
    // reconnects signaling, re-ensures room + channels, re-derives known-device
    // channels, re-probes relayed links for a direct path, says we're back, then
    // rebuilds every dead link. Debounced (M3) so a burst of network events (a
    // single handoff often fires online + connection-change + visibility within
    // a few hundred ms) does not thrash the reconnect/rebuild work.
    let recoverTimer = null
    const runRecovery = () => {
      sigRef.current?.reconnect?.()
      sessionRef.current?.kick() // C30: re-ensure room + channels the freeze may have eaten
      subscribeKnown() // re-derive channels in case a secret was stored while hidden
      nudgeUpgradeProbes() // P5: a network change may expose a direct path, re-probe relayed links
      for (const link of linksRef.current.values()) link.sendBack?.()
      // #13 (measured live): two mobile tabs rarely negotiate while both awake,
      // links that failed while WE were frozen stay failed forever. Reset retry
      // budgets (incl. second-wind markers, they share this map) and rebuild
      // every dead link. M3: on a wifi<->cellular handoff the old ICE path is
      // black-holed, so rebuilding 'disconnected'/'failed'/'closed' links is
      // exactly the right response, not just a relay probe.
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
    }
    const recover = () => {
      // Debounce: collapse a burst of triggers into one repair pass.
      if (recoverTimer) return
      recoverTimer = setTimeout(() => {
        recoverTimer = null
        runRecovery()
      }, 250)
    }
    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        recover()
      } else {
        for (const link of linksRef.current.values()) link.sendBrb?.(120)
      }
    }
    // M3: a network change is a full recovery trigger, not just a relay probe. On
    // wifi<->cellular the active interface (and our public IP) changes, so the old
    // ICE path is dead; recover() reconnects signaling AND rebuilds dead links.
    // (recover() already calls nudgeUpgradeProbes, so the P5 relay probe still
    // runs too.) These also fire `online` immediately on a handoff.
    const onNetworkChange = () => recover()
    // M4: BFCache / iOS Safari. iOS can freeze a tab into BFCache firing ONLY
    // pagehide (not visibilitychange); restore via pageshow with persisted:true.
    // pagehide -> tell peers brb (mirrors the hidden branch). pageshow (persisted)
    // -> run the shared recovery. Both share the debounce with visibility so a
    // pageshow that also fires visibilitychange does not double-repair.
    const onPageHide = () => {
      for (const link of linksRef.current.values()) link.sendBrb?.(120)
    }
    const onPageShow = (e) => {
      if (e && e.persisted) recover()
    }
    document.addEventListener('visibilitychange', onVisibility)
    window.addEventListener('focus', onVisibility)
    window.addEventListener('pagehide', onPageHide)
    window.addEventListener('pageshow', onPageShow)
    // M3: `online` and the Network Information API change now drive a FULL recovery
    // (reconnect signaling + rebuild dead links), not just the P5 relay probe.
    window.addEventListener('online', onNetworkChange)
    const conn = typeof navigator !== 'undefined' && navigator.connection
    conn?.addEventListener?.('change', onNetworkChange)
    return () => {
      if (recoverTimer) clearTimeout(recoverTimer)
      document.removeEventListener('visibilitychange', onVisibility)
      window.removeEventListener('focus', onVisibility)
      window.removeEventListener('pagehide', onPageHide)
      window.removeEventListener('pageshow', onPageShow)
      window.removeEventListener('online', onNetworkChange)
      conn?.removeEventListener?.('change', onNetworkChange)
    }
  }, [subscribeKnown])

  // ---- Part C: optional native LAN-discovery helper ------------------------
  // If the Filament Local helper (experiments/localsend-discovery) is running,
  // it exposes peers it found on the LAN via mDNS/UDP at 127.0.0.1:53317.
  // Browsers may fetch http://localhost from a secure page, so this lights up
  // automatically when present and stays silent (available:false) when not.
  useEffect(() => {
    let alive = true
    let t = null
    const HELPER = 'http://127.0.0.1:53317/peers'
    // The helper is OPTIONAL and absent on a normal user's machine. A single
    // refused fetch floods the console (net::ERR_CONNECTION_REFUSED), so we
    // probe ONCE, and only start the steady 3s poll if that first probe SUCCEEDS
    // (helper present). On failure we go silent: no interval, no retries, no
    // console spam. Worst case the helper started after page-load and isn't
    // picked up until reload, an acceptable trade for a quiet console.
    const poll = async () => {
      try {
        const res = await fetch(HELPER, { signal: AbortSignal.timeout(800) })
        const data = await res.json()
        if (!alive) return
        setLocalHelper({ available: true, peers: data.peers || [] })
        return true
      } catch {
        if (alive) setLocalHelper({ available: false, peers: [] })
        return false
      }
    }
    // First (and possibly only) probe. Light up the steady poll iff it's there.
    poll().then((present) => {
      if (alive && present && !t) t = setInterval(poll, 3000)
    })
    return () => {
      alive = false
      if (t) clearInterval(t)
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
    network, // 'ipv4' | 'ipv6' | 'raw': how the auto room was grouped
    signalingKind,
    connected,
    localHelper, // { available, peers }: Part C native LAN discovery
    sendFiles,
    acceptTransfer,
    declineTransfer,
    saveTransfer,
    clearTransfer,
    pairStatus, // null | 'pairing' | 'paired' | a user-facing error/refusal string
    pairWithCode, // join a code room to pair across networks
    receiveWithCode, // L1-a: claim a code, ephemeral-PAKE auth, then RECEIVE a file (secret discarded)
    generateCode, // mint a fresh code and switch to it; returns the code
    useAutoRoom, // go back to the 'people near you' auto room
    knownDevices, // C12: [{name, secret, addedAt}], remembered devices
    forgetDevice, // C12: drop a remembered device by name
    renameDevice, // edit a remembered device's local petname (no backend)
    pendingKeeps, // C27: [{peerId, name}], peers asking to be remembered
    acceptKeep, // C27: store the secret + ack; auto-connect from now on
    declineKeep, // C27: refuse; the sender discards its half too
    pendingPakeKeep, // L1-a: [{peerId, name, secret, caps}], v2 pairings awaiting remember-consent
    acceptPakeKeep, // L1-a: store the v2 device under the chosen name (local-only)
    declinePakeKeep, // L1-a: don't remember (K stays agreed)
    getLink: (pid) => linksRef.current.get(pid), // web-shell: the live PeerLink for a peer
    // web-shell (#4): resolve the CURRENT link for a device by its STABLE uid. A
    // reconnect supersedes the link under a new sid (the per-tab peer id changes),
    // so a terminal session that remembers only the old id would lose its link.
    // Looking up by uid finds the fresh link, letting WebTerminal reattach.
    getLinkByUid: (uid) => {
      if (!uid) return null
      for (const l of linksRef.current.values()) {
        if (l.peerUid === uid) return l
      }
      return null
    },
  }
}
