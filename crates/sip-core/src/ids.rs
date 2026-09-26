//! Random identifier generators: Via branches (RFC 3261 §8.1.1.7), To/From
//! tags (§19.3) and Call-IDs (§19.1.1.j). The `*_from_rng` variants accept
//! any [`rand::Rng`] for deterministic (seeded) generation, e.g. in tests.

use rand::Rng;

fn hex_from_rng<const N: usize, R: Rng>(rng: &mut R) -> String {
    let mut buf = [0u8; N];
    rng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Generates a new Via branch parameter: `z9hG4bK` + 16 hex characters
/// (the magic cookie marks branch compat with RFC 2543 detectors).
pub fn new_branch() -> String {
    branch_from_rng(&mut rand::thread_rng())
}

/// Generates a new 12 hex character To/From tag.
pub fn new_tag() -> String {
    tag_from_rng(&mut rand::thread_rng())
}

/// Generates a new Call-ID: 16 hex characters `@` `host`.
pub fn new_call_id(host: &str) -> String {
    call_id_from_rng(&mut rand::thread_rng(), host)
}

/// Deterministic [`new_branch`] driven by the supplied RNG.
pub fn branch_from_rng<R: Rng>(rng: &mut R) -> String {
    format!("z9hG4bK{}", hex_from_rng::<8, R>(rng))
}

/// Deterministic [`new_tag`] driven by the supplied RNG.
pub fn tag_from_rng<R: Rng>(rng: &mut R) -> String {
    hex_from_rng::<6, R>(rng)
}

/// Deterministic [`new_call_id`] driven by the supplied RNG.
pub fn call_id_from_rng<R: Rng>(rng: &mut R, host: &str) -> String {
    format!("{}@{host}", hex_from_rng::<8, R>(rng))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn branch_shape() {
        let b = new_branch();
        assert!(b.starts_with("z9hG4bK"));
        assert_eq!(b.len(), 7 + 16);
        assert!(b[7..]
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn tag_shape() {
        let t = new_tag();
        assert_eq!(t.len(), 12);
        assert!(t
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn call_id_shape() {
        let c = new_call_id("atlanta.example.com");
        assert!(c.ends_with("@atlanta.example.com"));
        let (local, host) = c.split_once('@').expect("call-id contains @");
        assert_eq!(local.len(), 16);
        assert!(local.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(host, "atlanta.example.com");
    }

    #[test]
    fn deterministic_with_seeded_rng() {
        let mut rng = StdRng::seed_from_u64(42);
        let b1 = branch_from_rng(&mut rng);
        let t1 = tag_from_rng(&mut rng);
        let c1 = call_id_from_rng(&mut rng, "h");
        let mut rng2 = StdRng::seed_from_u64(42);
        assert_eq!(b1, branch_from_rng(&mut rng2));
        assert_eq!(t1, tag_from_rng(&mut rng2));
        assert_eq!(c1, call_id_from_rng(&mut rng2, "h"));
    }

    #[test]
    fn unique_over_many_calls() {
        let set: std::collections::HashSet<String> = (0..1000).map(|_| new_branch()).collect();
        assert_eq!(set.len(), 1000);
        let tags: std::collections::HashSet<String> = (0..1000).map(|_| new_tag()).collect();
        assert_eq!(tags.len(), 1000);
    }
}
