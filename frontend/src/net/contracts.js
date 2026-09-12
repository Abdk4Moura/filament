// net/contracts.js — the layer boundaries for the filament networking stack.
//
// This file defines (as JSDoc interfaces — no runtime code) the three seams the
// consolidation is built on. The whole point: each layer depends only on the
// INTERFACE of the layer below, never its implementation. See
// docs/archive/plans/consolidation-plan-2026-06-15.md for the why; CONTRACT.md for the wire bytes.
//
//   ┌─ APPLICATION (useFilament, web-shell) ─────────────────────────┐
//   ├─ ORCHESTRATION (PeerLink: wires the three below per peer) ──────┤
//   ├─ RESILIENCE ───────────────┬─ PROTOCOL (the filament protocol) ─┤
//   └─ TRANSPORT (the physical link; WebRTC here) ───────────────────-┘
//
// The ONE rule that keeps PROTOCOL and RESILIENCE un-mangled:
//   if it has a timeout, a retry, or a reconnect → it is RESILIENCE, never
//   PROTOCOL. PROTOCOL is pure codec + ceremony state; it never owns a timer.

/**
 * TRANSPORT — moves opaque bytes/text over one physical link. Knows nothing
 * about message meaning, retries, or reconnection. RESILIENCE may ask it to
 * restart ICE or report its route; PROTOCOL only sends/receives through it.
 *
 * @typedef {Object} Transport
 * @property {boolean} open                         // channel.readyState === 'open'
 * @property {(u8: Uint8Array) => void} sendBinary  // a framed binary message
 * @property {(s: string) => void} sendText         // a control message (JSON)
 * @property {(cb: (data: string|ArrayBuffer) => void) => void} onMessage
 * @property {(cb: (state: 'connecting'|'open'|'closed') => void) => void} onStateChange
 * @property {() => Promise<TransportRoute|null>} getRoute
 * @property {() => void} restartIce
 * @property {() => void} close
 */

/** @typedef {'local'|'direct'|'relayed'} TransportRoute */

/**
 * PROTOCOL CODEC — the filament wire format. Pure functions, no I/O, no timers,
 * no browser APIs (so it runs under plain `node` in characterization tests and
 * stays byte-identical to the Rust side per CONTRACT.md). Ceremony state machines
 * (PAKE pairing, file-transfer) are separate PROTOCOL modules that build on this.
 *
 * @typedef {Object} ProtocolCodec
 * @property {(sid: number, payload: Uint8Array) => Uint8Array} frame
 * @property {(buf: ArrayBuffer) => ({sid: number, payload: Uint8Array}|null)} parseFrame
 * @property {(obj: object) => string} encodeControl
 * @property {(s: string) => object} decodeControl
 * @property {(n: number) => number} highHalfSid
 */

/**
 * RESILIENCE CONTROLLER — keeps a link alive and data delivered despite a hostile
 * network. Owns ALL timers/retries/reconnect decisions. Depends on a Transport
 * handle (to restart/switch) and is fed progress signals by the orchestration
 * layer; it never parses protocol bytes itself.
 *
 * @typedef {Object} ResilienceController
 * @property {() => void} start
 * @property {() => void} stop
 * @property {(bytes: number) => void} noteProgress  // data path is alive
 * @property {(route: TransportRoute) => void} noteRoute
 */

export {} // interfaces only; no runtime export
