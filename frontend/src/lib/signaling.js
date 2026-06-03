// Signaling abstraction.
//
// The rest of the app talks to ONE interface and doesn't care whether the
// signaling actually travels over Socket.IO (our Flask relay) or Firebase
// Firestore. Pick the implementation at runtime from /api/config.
//
//   const sig = await createSignaling()
//   sig.on('welcome',     ({ id, peers }) => {})
//   sig.on('peer-joined', ({ id, name })  => {})
//   sig.on('peer-left',   ({ id })        => {})
//   sig.on('signal',      ({ from, data })=> {})
//   sig.join(room, name)
//   sig.signal(toPeerId, data)
//   sig.leave()
//
// Both implementations emit the SAME four inbound events and accept the same
// join/signal/leave calls — that is the whole point of the abstraction.

import { io } from 'socket.io-client'

class Emitter {
  #handlers = {}
  on(event, cb) {
    ;(this.#handlers[event] ||= []).push(cb)
    return this
  }
  _emit(event, payload) {
    ;(this.#handlers[event] || []).forEach((cb) => cb(payload))
  }
}

// ---------------------------------------------------------------- Socket.IO --
class SocketIOSignaling extends Emitter {
  constructor() {
    super()
    this.kind = 'socketio'
    this.socket = io({ autoConnect: true })
    for (const ev of ['welcome', 'peer-joined', 'peer-left', 'signal']) {
      this.socket.on(ev, (payload) => this._emit(ev, payload))
    }
  }
  join(room, name) {
    this.room = room
    this.socket.emit('join', { room, name })
  }
  signal(to, data) {
    this.socket.emit('signal', { to, data })
  }
  leave() {
    this.socket.emit('leave', {})
  }
}

// ----------------------------------------------------------------- Firebase --
// Serverless signaling over Firestore. Loaded lazily so the Firebase SDK is
// only pulled in when SIGNALING=firebase. Presence + per-peer signal mailboxes
// mirror the Socket.IO event contract exactly.
class FirebaseSignaling extends Emitter {
  constructor(firebaseConfig) {
    super()
    this.kind = 'firebase'
    this.config = firebaseConfig
    this._ready = this.#init()
  }
  async #init() {
    // Optional dependency: only loaded in firebase mode. Install it with
    // `npm install firebase` before setting QS_SIGNALING=firebase. @vite-ignore
    // keeps the default (socket.io) build from trying to bundle it.
    const [{ initializeApp }, fs] = await Promise.all([
      import(/* @vite-ignore */ 'firebase/app'),
      import(/* @vite-ignore */ 'firebase/firestore'),
    ])
    this.fs = fs
    this.db = fs.getFirestore(initializeApp(this.config))
    this.id = 'fb_' + Math.random().toString(36).slice(2, 10)
  }
  async join(room, name) {
    await this._ready
    const { doc, setDoc, collection, onSnapshot, serverTimestamp } = this.fs
    this.room = room
    this.name = name
    const peersCol = collection(this.db, 'rooms', room, 'peers')

    // Existing peers become our "welcome"; then announce ourselves.
    const { getDocs } = this.fs
    const existing = (await getDocs(peersCol)).docs
      .filter((d) => d.id !== this.id)
      .map((d) => ({ id: d.id, name: d.data().name }))
    await setDoc(doc(peersCol, this.id), { name, joinedAt: serverTimestamp() })
    this._emit('welcome', { id: this.id, peers: existing })

    // Watch presence.
    this._unsubPeers = onSnapshot(peersCol, (snap) => {
      snap.docChanges().forEach((c) => {
        if (c.doc.id === this.id) return
        if (c.type === 'added') this._emit('peer-joined', { id: c.doc.id, name: c.doc.data().name })
        if (c.type === 'removed') this._emit('peer-left', { id: c.doc.id })
      })
    })
    // Watch our signal mailbox.
    const mailbox = collection(this.db, 'rooms', room, 'peers', this.id, 'inbox')
    this._unsubInbox = onSnapshot(mailbox, (snap) => {
      snap.docChanges().forEach((c) => {
        if (c.type !== 'added') return
        const { from, data } = c.doc.data()
        this._emit('signal', { from, data })
        this.fs.deleteDoc(c.doc.ref)
      })
    })
  }
  async signal(to, data) {
    await this._ready
    const { collection, addDoc } = this.fs
    await addDoc(collection(this.db, 'rooms', this.room, 'peers', to, 'inbox'), {
      from: this.id,
      data,
    })
  }
  async leave() {
    await this._ready
    this._unsubPeers?.()
    this._unsubInbox?.()
    const { doc, deleteDoc } = this.fs
    await deleteDoc(doc(this.db, 'rooms', this.room, 'peers', this.id))
  }
}

export async function createSignaling(appConfig) {
  if (appConfig.signaling === 'firebase' && appConfig.firebase) {
    return new FirebaseSignaling(appConfig.firebase)
  }
  return new SocketIOSignaling()
}
