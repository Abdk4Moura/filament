#!/usr/bin/env node
// Filament Local — a spike of true offline LAN discovery (the LocalSend model).
//
// A browser tab can't see other devices on the WiFi: JS has no UDP/multicast and
// no mDNS. So discovery that works with NO internet and NO server needs a tiny
// native helper on each machine. This is that helper, in dependency-free Node.
//
//   • Presence:  every device multicasts a small "I'm here" datagram on the LAN
//                and listens for everyone else's. (A pragmatic stand-in for full
//                mDNS / Bonjour — same idea: announce + discover over multicast.)
//   • Bridge:    it exposes whoever it found at http://127.0.0.1:53317/peers, so
//                the Filament web app (running locally) can render LAN devices
//                even with the internet unplugged. WebRTC/HTTP handoff for the
//                actual transfer would build on top of this.
//
// Run two on one machine to see them find each other:
//   node discovery.js --name alice
//   node discovery.js --name bob --http 53318
//
// Then: curl http://127.0.0.1:53317/peers

import dgram from 'node:dgram'
import http from 'node:http'
import os from 'node:os'
import crypto from 'node:crypto'

// ---- config (flags > env > default) ---------------------------------------
const arg = (flag, def) => {
  const i = process.argv.indexOf(flag)
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : def
}
const GROUP = '239.255.79.17' // admin-scoped multicast, off the real mDNS group
const MPORT = Number(arg('--mport', process.env.FIL_MPORT || 53318))
const HTTP_PORT = Number(arg('--http', process.env.FIL_HTTP || 53317))
const NAME = arg('--name', os.hostname())
const ID = crypto.randomBytes(6).toString('hex')
const ANNOUNCE_MS = 2000
const EXPIRE_MS = 6000

// ---- presence over multicast ----------------------------------------------
const peers = new Map() // id -> { id, name, http, addr, lastSeen }
const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true })

sock.on('message', (buf, rinfo) => {
  let msg
  try {
    msg = JSON.parse(buf.toString())
  } catch {
    return
  }
  if (msg.t !== 'announce' || msg.id === ID) return // ignore noise + our own echo
  peers.set(msg.id, { id: msg.id, name: msg.name, http: msg.http, addr: rinfo.address, lastSeen: Date.now() })
})

sock.bind(MPORT, () => {
  try {
    sock.addMembership(GROUP)
  } catch (e) {
    console.error('addMembership failed (no multicast-capable interface?):', e.message)
  }
  sock.setMulticastLoopback(true) // so peers on the SAME host can see each other
  sock.setMulticastTTL(1) // stay on the local link, never route off the LAN
  console.log(`[${NAME}] announcing as ${ID} on ${GROUP}:${MPORT}`)
})

const announce = () => {
  const buf = Buffer.from(JSON.stringify({ t: 'announce', id: ID, name: NAME, http: HTTP_PORT }))
  sock.send(buf, MPORT, GROUP)
}
setInterval(announce, ANNOUNCE_MS)
announce()

// Drop peers we haven't heard from recently.
setInterval(() => {
  const now = Date.now()
  for (const [id, p] of peers) if (now - p.lastSeen > EXPIRE_MS) peers.delete(id)
}, 1000)

// ---- localhost bridge for the browser -------------------------------------
const cors = (res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Content-Type', 'application/json')
}
const server = http.createServer((req, res) => {
  cors(res)
  if (req.url === '/me') return res.end(JSON.stringify({ id: ID, name: NAME }))
  if (req.url === '/health') return res.end(JSON.stringify({ ok: true }))
  if (req.url === '/peers') {
    const list = [...peers.values()].map(({ id, name, http, addr }) => ({ id, name, http, addr }))
    return res.end(JSON.stringify({ peers: list }))
  }
  res.statusCode = 404
  res.end(JSON.stringify({ error: 'not found' }))
})
// Bind to loopback only: the bridge is for the browser on THIS machine.
server.listen(HTTP_PORT, '127.0.0.1', () =>
  console.log(`[${NAME}] bridge at http://127.0.0.1:${HTTP_PORT}/peers`),
)

const shutdown = () => {
  try { sock.dropMembership(GROUP) } catch {}
  sock.close()
  server.close()
  process.exit(0)
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
