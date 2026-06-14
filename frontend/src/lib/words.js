// Speakable pairing wordlists: CLIENT-SIDE minting (spec §2.0). The browser
// mints the words locally; the server NEVER sees or generates them. Mirrors
// pake/src/words.rs. 2^12: 64 adj × 64 animal = 4,096. Minted codes are
// 3-segment `adj-animal-NNNN` (the same shape as a transfer code).
//
// The words are NOT crypto-load-bearing for K agreement (K depends only on the
// typed string, normalized by the shared normCode). This list governs entropy
// + sayability. It need not be byte-identical to the Rust list, but we keep it
// in sync for a consistent UX. The EXTRA list is kept exported (was the third
// minted word; no longer used by mintWords) for any user-chosen 4-word code.

export const ADJ = [
  'amber', 'bold', 'brave', 'brisk', 'calm', 'cheery', 'chill', 'civil',
  'clever', 'cosy', 'crisp', 'daring', 'deft', 'dewy', 'eager', 'early',
  'fancy', 'fiery', 'fleet', 'fond', 'frank', 'free', 'fresh', 'gentle',
  'giddy', 'glad', 'golden', 'grand', 'happy', 'hardy', 'hasty', 'honest',
  'humble', 'jolly', 'keen', 'kind', 'lively', 'loyal', 'lucky', 'lunar',
  'mellow', 'merry', 'mighty', 'misty', 'neat', 'noble', 'perky', 'plucky',
  'polar', 'proud', 'quick', 'quiet', 'rapid', 'rosy', 'royal', 'shiny',
  'snappy', 'solid', 'spry', 'stout', 'sunny', 'swift', 'tidy', 'witty',
]

export const ANIMAL = [
  'otter', 'panda', 'falcon', 'lynx', 'koala', 'heron', 'fox', 'ibex',
  'marten', 'tapir', 'badger', 'beaver', 'bison', 'bongo', 'camel', 'civet',
  'condor', 'crane', 'dingo', 'dove', 'eland', 'ermine', 'ferret', 'finch',
  'gecko', 'gibbon', 'hare', 'hawk', 'hyrax', 'jackal', 'kestrel', 'kiwi',
  'lemur', 'llama', 'macaw', 'magpie', 'mole', 'moose', 'murre', 'newt',
  'ocelot', 'okapi', 'oriole', 'osprey', 'owl', 'pika', 'plover', 'puffin',
  'quokka', 'rabbit', 'raven', 'robin', 'seal', 'shrew', 'skink', 'sparrow',
  'stoat', 'swan', 'tern', 'toucan', 'vole', 'wombat', 'wren', 'zebra',
]

export const EXTRA = [
  'azure', 'cobalt', 'coral', 'crimson', 'emerald', 'hazel', 'indigo', 'ivory',
  'jade', 'lilac', 'olive', 'rose', 'ruby', 'scarlet', 'teal', 'violet',
]

// Unbiased pick: all list lengths are powers of two (64, 16), so masking a
// 32-bit CSPRNG draw is exact.
function pick(list) {
  const buf = new Uint32Array(1)
  crypto.getRandomValues(buf)
  return list[buf[0] & (list.length - 1)]
}

/// Mint the WORDS half of a spoken code (the password): adj-animal. With the
/// nameplate appended the full minted code is `adj-animal-NNNN` (3 segments).
export function mintWords() {
  return `${pick(ADJ)}-${pick(ANIMAL)}`
}

/// Mint a 4-digit nameplate (the routing suffix the server sees). Widened to 4
/// digits (spec §2.2) so rendezvous capacity isn't the bottleneck. 1000..9999.
export function mintNameplate() {
  const buf = new Uint32Array(1)
  crypto.getRandomValues(buf)
  return String(1000 + (buf[0] % 9000))
}
