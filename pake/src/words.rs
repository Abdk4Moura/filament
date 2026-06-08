//! Speakable pairing wordlists — CLIENT-SIDE minting (spec §2.0, the
//! load-bearing change). The server NEVER sees or generates these words; it
//! only allocates/matches the numeric nameplate.
//!
//! Entropy (Decision #1: WIDEN to ~16 bits): 64 adjectives × 64 animals × 16
//! "extra" words = 65,536 = 2^16 passwords. The adjective/animal lists are the
//! existing vetted 64-word lists (short, common, phonetically distinct, easy to
//! SAY); the extra list is 16 common colors. Reusing the vetted lists avoids
//! the "256 sayable animals" problem (which forces obscure words).
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

/// 16 common, distinct, easy-to-say colors — the third entropy word.
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

/// Mint the WORDS half of a spoken code (the password): `adj-animal-extra`.
/// ~16 bits. Uses the OS CSPRNG.
pub fn mint_words() -> String {
    let mut rng = super::os_rng();
    format!("{}-{}-{}", pick(&mut rng, &ADJ), pick(&mut rng, &ANIMAL), pick(&mut rng, &EXTRA))
}

/// Mint with a caller RNG (tests/interop only).
pub fn mint_words_with(rng: &mut impl RngCore) -> String {
    format!("{}-{}-{}", pick(rng, &ADJ), pick(rng, &ANIMAL), pick(rng, &EXTRA))
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
        // 64*64*16 = 65536 = 2^16 — the widened password entropy (Decision #1).
        assert_eq!(ADJ.len() * ANIMAL.len() * EXTRA.len(), 1 << 16);
    }

    #[test]
    fn minted_words_are_three_parts() {
        let w = mint_words();
        let parts: Vec<&str> = w.split('-').collect();
        assert_eq!(parts.len(), 3, "adj-animal-extra");
    }
}
