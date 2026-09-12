// PROTOCOL layer — the filament FILE-TRANSFER ceremony.
//
// This module owns the *vocabulary* and the *pure decisions* of the
// offer/accept/end/delivery-ack state machine, extracted from webrtc.js
// (`_streamFile` / `_finishReceive` / `_onControl`). It mirrors the CLI's
// send_cmd/recv_cmd protocol and the wire shapes are FROZEN (CONTRACT.md).
//
// Discipline (docs/archive/plans/consolidation-GOAL-2026-06-16.md §3 "un-mangling rule"): PROTOCOL is pure —
// it builds control-message shapes and decides "what should happen next" from
// plain inputs. It owns NO timer, NO retry, NO transport, NO instance state and
// NO browser API. The mutable transfer bookkeeping (this.transfers / partials /
// outgoing stores), the actual Blob assembly + sha256, the channel sends, and
// the no-ack TIMER all stay in PeerLink (orchestration) / resilience. That keeps
// every piece here directly node-testable, like wire.js.

import { MSG } from './wire.js'

// ---- control-message builders -------------------------------------------------
// The exact JSON shapes that cross the wire. Key insertion order is preserved
// from the original inline literals so the encoded bytes stay byte-identical
// (CONTRACT.md is frozen; the CLI parses order-independently, but we don't rely
// on that). A send/resume offer carries the head digest (C7 resume) and the
// whole-file digest (P4 integrity) when they are available.
export function offerMsg({ id, sid, name, size, mime, resume, head, full }) {
  return {
    type: MSG.OFFER,
    id,
    sid,
    name,
    size,
    mime,
    ...(resume ? { resume: true } : {}),
    ...(head ? { head } : {}),
    ...(full ? { full } : {}),
  }
}

export const acceptMsg = (id, offset = 0) => ({ type: MSG.ACCEPT, id, offset })
export const declineMsg = (id) => ({ type: MSG.DECLINE, id })
export const endMsg = (id, sid) => ({ type: MSG.END, id, sid })
// P4: a delivery-ack is sent ONLY after the whole file verified (sha256 matched).
export const deliveryAckMsg = (id, sid) => ({ type: MSG.DELIVERY_ACK, id, sid, v: 1 })

// ---- receiver: how to handle an incoming OFFER --------------------------------
// If we already hold partial bytes for a re-offered (resume) transfer, the user
// already consented once, so accept automatically from where we left off; else
// surface the offer for an accept/decline decision.
export function decideOnOffer({ resume, hasPartial }) {
  return resume && hasPartial ? { action: 'auto-accept' } : { action: 'surface' }
}

// ---- receiver: whole-file verify decision at CTRL.END -------------------------
// Pure decision AFTER the body has been hashed and compared to the offered
// digest. Precondition: a digest WAS offered and the body WAS hashable — the
// no-digest (legacy peer) and no-crypto (insecure origin) cases finalize
// directly without hashing and are handled by the caller, since they are IO
// guards, not protocol decisions.
//   hashMatches  the recomputed sha256 equals the offered whole-file digest
//   received     bytes accumulated so far
//   size         the offered file size
//   verifyFails  how many times this transfer has failed verification (>=1 here)
//   maxFails     the bound after which we give up cleanly (partial kept)
// Returns one of:
//   { action: 'finalize-ack' }                    intact → finalize + ack
//   { action: 'fail' }                            over the bound → paused/resumable
//   { action: 'rerequest', offset, reset }        re-ask the sender from `offset`;
//        reset=true means the buffers are poisoned (full size, wrong hash) and
//        must be cleared (restart from 0); reset=false is a truncated tail that
//        resumes from the current offset.
export function decideAfterVerify({ hashMatches, received, size, verifyFails, maxFails }) {
  if (hashMatches) return { action: 'finalize-ack' }
  if (verifyFails > maxFails) return { action: 'fail' }
  const truncated = received < (size || 0)
  return truncated
    ? { action: 'rerequest', offset: received, reset: false }
    : { action: 'rerequest', offset: 0, reset: true }
}

// ---- sender: what a send should do when the no-ack window elapses -------------
// A send is "complete" (delivered + verified) ONLY on a genuine
// CTRL.DELIVERY_ACK, so this NEVER returns 'complete'. Pure (no side effects);
// the TIMER that arms this window lives in PeerLink/resilience, not here.
//
//   channelOpen   data channel readyState === 'open'
//   connected     pc.connectionState === 'connected'
//   peerHasAcked  this peer has delivery-acked before (this link or a past one)
//   offeredDigest we shipped a whole-file digest in the OFFER (receiver acks)
//   reprobed      we have already re-sent END once this window
// Returns:
//   { action: 'reprobe' }            re-send END once and extend the window
//   { action: 'fail', resumable }    end honestly, never claim success
export function decideAckFallback({ channelOpen, connected, peerHasAcked, offeredDigest, reprobed }) {
  const healthy = !!channelOpen && !!connected
  // Link looks dead: nothing arrived and we cannot prompt a re-ack. End honestly.
  if (!healthy) return { action: 'fail', resumable: true }
  // Link looks alive and we have not yet re-probed: the ack may simply have been
  // lost. Re-send END once to prompt the receiver to re-ack, extend the window.
  if (!reprobed) return { action: 'reprobe' }
  // Re-probed, still no ack. We must not claim success: a peer that ever acked, or
  // one we offered a digest to, is EXPECTED to ack, treat the silence as a failure
  // (resumable). With the modern fleet every receiver acks, so this is the norm.
  void peerHasAcked
  void offeredDigest
  return { action: 'fail', resumable: true }
}

// ---- sender: reconcile a peer's CTRL.STATE digest ----------------------------
// The peer periodically reports how many bytes it holds per transfer. If we
// believe a SEND is complete but the peer holds fewer bytes than the file size,
// the tail/END was lost — re-offer (resume). Returns the ids to resume. Pure:
// the caller looks each id up in its own transfer map and re-offers.
export function sendsToResume(peerTransfers, localSends) {
  const ids = []
  for (const [id, bytes] of Object.entries(peerTransfers || {})) {
    const t = localSends.get(id)
    if (t && t.direction === 'send' && t.status === 'complete' && bytes < t.size) ids.push(id)
  }
  return ids
}
