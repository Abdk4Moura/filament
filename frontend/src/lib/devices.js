// Known devices: the browser half of persistent pairing (C12/C20).
//
// A "known device" is a {name, secret} pair persisted in localStorage. The
// secret is E2E — the server only ever sees sha256("filament-pair:"+secret),
// the meeting-point channel two holders subscribe to. Mutual acknowledgement
// is structural: presence lights up ONLY when both sides hold the secret and
// raise the same channel; trust is asserted per-link with an HMAC proof bound
// to the link's DTLS fingerprints, so neither the server nor a MITM can
// impersonate a known device.
//
// This mirrors the CLI exactly (cli/src/main.rs channel_of / proof_for) — the
// strings MUST stay byte-identical or browsers and CLIs stop recognizing
// each other.

const KEY = 'filament-known-devices'

export function devicesLoad() {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) || '[]')
    return Array.isArray(v) ? v.filter((d) => d && d.name && /^[0-9a-f]{64}$/.test(d.secret || '')) : []
  } catch {
    return []
  }
}

export function devicesStore(name, secret) {
  const list = devicesLoad().filter((d) => d.secret !== secret)
  list.push({ name, secret, addedAt: Date.now() })
  try {
    localStorage.setItem(KEY, JSON.stringify(list))
  } catch (e) {
    // Private Browsing / storage blocked: the device won't be remembered and
    // auto-reconnect won't work — say so where a debugger will look.
    console.warn('filament: could not persist known device (private browsing?)', e)
  }
  return list
}

/// L1-a (spec §8): store a v2 device record with its agreed capability set.
/// Grows the record with `v` and `caps` (deny-by-default; "transfer" is the L0
/// baseline). The {name, secret} fields are unchanged so the reconnect path
/// (devicesLoad / channelOf / proofFor) keeps working byte-for-byte.
export function devicesStoreV2(name, secret, caps) {
  const list = devicesLoad().filter((d) => d.secret !== secret)
  list.push({ name, secret, v: 2, caps: caps || ['transfer'], addedAt: Date.now() })
  try {
    localStorage.setItem(KEY, JSON.stringify(list))
  } catch (e) {
    console.warn('filament: could not persist known device (private browsing?)', e)
  }
  return list
}

/// L1-a (spec §8): a device's granted capabilities. v1 records (no caps) read
/// as ["transfer"] for back-compat. Returns null if the device isn't known.
export function deviceCaps(name) {
  const d = devicesLoad().find((x) => x.name === name)
  if (!d) return null
  return Array.isArray(d.caps) ? d.caps : ['transfer']
}

/// L1-a (spec §8 / gate 5): deny-by-default capability check. "transfer" is the
/// always-allowed L0 baseline; future caps must be explicitly granted.
export function deviceAllows(name, capability) {
  if (capability === 'transfer') return true
  const caps = deviceCaps(name)
  return !!caps && caps.includes(capability)
}

export function devicesForget(name) {
  const list = devicesLoad().filter((d) => d.name !== name)
  try {
    localStorage.setItem(KEY, JSON.stringify(list))
  } catch {}
  return list
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
const utf8 = (s) => new TextEncoder().encode(s)

/// The server-visible meeting point: sha256("filament-pair:" + secret), hex.
export async function channelOf(secret) {
  return hex(await crypto.subtle.digest('SHA-256', utf8('filament-pair:' + secret)))
}

/// C20 proof: HMAC-SHA256(secret, "filament-proof2:{prover}|{loUid}|{hiUid}|{loFp}|{hiFp}").
/// uids and fingerprints are order-normalized so both sides derive the same
/// message; the prover's uid tags direction so a proof can't be replayed back.
export async function proofFor(secret, proverUid, aUid, bUid, fp1, fp2) {
  const [lo, hi] = aUid < bUid ? [aUid, bUid] : [bUid, aUid]
  const [fLo, fHi] = fp1 < fp2 ? [fp1, fp2] : [fp2, fp1]
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return hex(await crypto.subtle.sign('HMAC', key, utf8(`filament-proof2:${proverUid}|${lo}|${hi}|${fLo}|${fHi}`)))
}

/// Same parse as the CLI's sdp_fingerprint: the full `a=fingerprint:` value,
/// trimmed and uppercased (e.g. "SHA-256 AB:CD:…").
export function sdpFingerprint(sdp) {
  const line = (sdp || '').split(/\r?\n/).find((l) => l.startsWith('a=fingerprint:'))
  return line ? line.slice('a=fingerprint:'.length).trim().toUpperCase() : null
}
