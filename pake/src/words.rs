//! Speakable pairing wordlists — CLIENT-SIDE minting (spec §2.0, the
//! load-bearing change). The server NEVER sees or generates these words; it
//! only allocates/matches the numeric nameplate.
//!
//! Entropy: 64 adjectives × 64 animals = 4,096 = 2^12 passwords. Minted codes
//! are 3-segment `adj-animal-NNNN` (e.g. brave-otter-3141) — the same shape as
//! a transfer code, so there is one code shape to learn. The adjective/animal
//! lists are the existing vetted 64-word lists (short, common, phonetically
//! distinct, easy to SAY). The 2^12 password floor is sound because the words
//! never reach the server (relay-blind SPAKE2) and online guessing is bounded
//! by claim-burn + the 5-claims/min rate-limit (≈1 guess per code, no offline
//! attack). The `EXTRA` color list is kept defined (for any caller that still
//! references it / for user-chosen 4-word codes) but is NO LONGER used by mint.
//!
//! NOTE: these words are NOT crypto-load-bearing for K agreement — K depends
//! only on the literal typed string, normalized identically on both ends
//! (`norm_code`). The list only governs entropy + sayability. The browser keeps
//! its own copy (frontend/src/lib/words.js); the two need not be byte-identical
//! (a minted word just has to be typeable), but we keep them in sync for UX.

use rand_core::RngCore;

pub const ADJ: [&str; 64] = [
    "amber", "bold", "brave", "brisk", "calm", "cheery", "chill", "civil",
    "clever", "cosy", "crisp", "daring", "deft", "dewy", "eager", "early",
    "fancy", "fiery", "fleet", "fond", "frank", "free", "fresh", "gentle",
    "giddy", "glad", "golden", "grand", "happy", "hardy", "hasty", "honest",
    "humble", "jolly", "keen", "kind", "lively", "loyal", "lucky", "lunar",
    "mellow", "merry", "mighty", "misty", "neat", "noble", "perky", "plucky",
    "polar", "proud", "quick", "quiet", "rapid", "rosy", "royal", "shiny",
    "snappy", "solid", "spry", "stout", "sunny", "swift", "tidy", "witty",
];

pub const ANIMAL: [&str; 64] = [
    "otter", "panda", "falcon", "lynx", "koala", "heron", "fox", "ibex",
    "marten", "tapir", "badger", "beaver", "bison", "bongo", "camel", "civet",
    "condor", "crane", "dingo", "dove", "eland", "ermine", "ferret", "finch",
    "gecko", "gibbon", "hare", "hawk", "hyrax", "jackal", "kestrel", "kiwi",
    "lemur", "llama", "macaw", "magpie", "mole", "moose", "murre", "newt",
    "ocelot", "okapi", "oriole", "osprey", "owl", "pika", "plover", "puffin",
    "quokka", "rabbit", "raven", "robin", "seal", "shrew", "skink", "sparrow",
    "stoat", "swan", "tern", "toucan", "vole", "wombat", "wren", "zebra",
];

/// 16 common, distinct, easy-to-say colors. Formerly the third minted entropy
/// word; minting is now 3-segment `adj-animal-NNNN`, so this is no longer used
/// by `mint_words`. Kept defined for user-chosen 4-word codes / interop.
#[allow(dead_code)]
pub const EXTRA: [&str; 16] = [
    "azure", "cobalt", "coral", "crimson", "emerald", "hazel", "indigo", "ivory",
    "jade", "lilac", "olive", "rose", "ruby", "scarlet", "teal", "violet",
];

/// CSPRNG-uniform pick (rejection-free since all list lengths divide 2^32 here:
/// 64 and 16 are powers of two, so masking is exact and unbiased).
fn pick<'a>(rng: &mut impl RngCore, list: &[&'a str]) -> &'a str {
    let n = list.len() as u32;
    debug_assert!(n.is_power_of_two(), "lists must be powers of two for unbiased pick");
    let mask = n - 1;
    list[(rng.next_u32() & mask) as usize]
}

/// Mint the WORDS half of a spoken code (the password): `adj-animal`.
/// 2^12 (4,096). Uses the OS CSPRNG. The full minted code is `adj-animal-NNNN`
/// (3 segments) once the nameplate is appended.
pub fn mint_words() -> String {
    let mut rng = super::os_rng();
    format!("{}-{}", pick(&mut rng, &ADJ), pick(&mut rng, &ANIMAL))
}

/// Mint with a caller RNG (tests/interop only).
pub fn mint_words_with(rng: &mut impl RngCore) -> String {
    format!("{}-{}", pick(rng, &ADJ), pick(rng, &ANIMAL))
}

/// Mint a 4-digit nameplate (the routing suffix the server sees). Widened to 4
/// digits (spec §2.2) so rendezvous capacity isn't the bottleneck: 1000..=9999.
/// This is the ONLY part of the code that ever reaches the server.
pub fn mint_nameplate() -> String {
    let mut rng = super::os_rng();
    format!("{}", 1000 + (rng.next_u32() % 9000))
}

/// Assemble the full spoken code the user reads aloud: `<words>-<nameplate>`.
pub fn mint_spoken_code() -> String {
    format!("{}-{}", mint_words(), mint_nameplate())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_unique_and_sized() {
        use std::collections::HashSet;
        assert_eq!(ADJ.len(), 64);
        assert_eq!(ANIMAL.len(), 64);
        assert_eq!(EXTRA.len(), 16);
        assert_eq!(ADJ.iter().collect::<HashSet<_>>().len(), 64);
        assert_eq!(ANIMAL.iter().collect::<HashSet<_>>().len(), 64);
        assert_eq!(EXTRA.iter().collect::<HashSet<_>>().len(), 16);
        // 64*64 = 4096 = 2^12 — the minted password entropy (3-seg adj-animal).
        assert_eq!(ADJ.len() * ANIMAL.len(), 1 << 12);
    }

    #[test]
    fn minted_words_are_two_parts() {
        // The WORDS half is `adj-animal`; with the nameplate appended the full
        // minted code is `adj-animal-NNNN` (3 segments).
        let w = mint_words();
        let parts: Vec<&str> = w.split('-').collect();
        assert_eq!(parts.len(), 2, "adj-animal");
        let full = mint_spoken_code();
        assert_eq!(full.split('-').count(), 3, "adj-animal-NNNN");
    }
}
