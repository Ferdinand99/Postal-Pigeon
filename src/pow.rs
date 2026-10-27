//! Registration proof of work (docs/design.md section 6.1).
//!
//! A challenge is stateless: eight bytes of issue time, sixteen random bytes
//! and a truncated HMAC over both, URL-safe base64. The relay remembers only
//! the ids of challenges it has accepted, until they expire, so each works
//! once. The client finds a `nonce` such that `SHA-256(challenge ‖ nonce)`
//! (both as their UTF-8 text) starts with `difficulty` zero bits.

use crate::clock::Clock;
use crate::crypto::{Keys, ct_eq, sha256};
use crate::util::{b64, b64_decode, leading_zero_bits, random_bytes};

const MAC_LEN: usize = 16;
const RAW_LEN: usize = 8 + 16 + MAC_LEN;
/// A challenge from the future (clock skew after a restart) is accepted up to this much.
const SKEW_SECS: i64 = 60;
/// Longest nonce accepted.
pub const MAX_NONCE_LEN: usize = 64;

/// A new challenge and the Unix time (seconds) it expires.
pub fn issue(keys: &Keys, clock: &Clock, ttl_secs: i64) -> (String, i64) {
    let issued = clock.now_secs();
    let mut body = Vec::with_capacity(RAW_LEN);
    body.extend_from_slice(&issued.to_be_bytes());
    body.extend_from_slice(&random_bytes::<16>());
    let mac = keys.challenge_mac(&body);
    body.extend_from_slice(&mac[..MAC_LEN]);
    (b64(&body), issued + ttl_secs)
}

/// Why a registration's proof of work was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    /// Not a challenge this relay issued.
    Invalid,
    /// Issued too long ago.
    Expired,
    /// The nonce doesn't meet the difficulty.
    BadProof,
}

/// Checks a challenge and its proof. On success returns the challenge's random
/// id, which the caller records as used.
pub fn verify(
    keys: &Keys,
    clock: &Clock,
    ttl_secs: i64,
    difficulty: u32,
    challenge: &str,
    nonce: &str,
) -> Result<[u8; 16], PowError> {
    if challenge.len() > 128 || nonce.is_empty() || nonce.len() > MAX_NONCE_LEN || !nonce.is_ascii()
    {
        return Err(PowError::Invalid);
    }
    let raw = b64_decode(challenge).ok_or(PowError::Invalid)?;
    if raw.len() != RAW_LEN {
        return Err(PowError::Invalid);
    }
    let (body, mac) = raw.split_at(RAW_LEN - MAC_LEN);
    if !ct_eq(&keys.challenge_mac(body)[..MAC_LEN], mac) {
        return Err(PowError::Invalid);
    }
    let issued = i64::from_be_bytes(body[..8].try_into().expect("8 bytes"));
    let now = clock.now_secs();
    if issued > now + SKEW_SECS {
        return Err(PowError::Invalid);
    }
    if now >= issued + ttl_secs {
        return Err(PowError::Expired);
    }
    let digest = sha256(&[challenge.as_bytes(), nonce.as_bytes()].concat());
    if leading_zero_bits(&digest) < difficulty {
        return Err(PowError::BadProof);
    }
    Ok(body[8..24].try_into().expect("16 bytes"))
}

/// Finds a nonce for `challenge`. What a client does; used by tests and docs.
pub fn solve(challenge: &str, difficulty: u32) -> String {
    for n in 0u64.. {
        let nonce = n.to_string();
        let digest = sha256(&[challenge.as_bytes(), nonce.as_bytes()].concat());
        if leading_zero_bits(&digest) >= difficulty {
            return nonce;
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_solve_verify() {
        let keys = Keys::ephemeral();
        let clock = Clock::new();
        let (c, exp) = issue(&keys, &clock, 300);
        assert_eq!(exp, clock.now_secs() + 300);
        let nonce = solve(&c, 8);
        assert!(verify(&keys, &clock, 300, 8, &c, &nonce).is_ok());
        // Stricter difficulty than the nonce was found for (almost surely) fails.
        assert_eq!(
            verify(&keys, &clock, 300, 32, &c, &nonce),
            Err(PowError::BadProof)
        );
    }

    #[test]
    fn rejects_foreign_tampered_and_expired() {
        let keys = Keys::ephemeral();
        let clock = Clock::new();
        let (c, _) = issue(&keys, &clock, 300);
        let nonce = solve(&c, 4);
        let other = Keys::ephemeral();
        assert_eq!(
            verify(&other, &clock, 300, 4, &c, &nonce),
            Err(PowError::Invalid)
        );
        let mut bad = c.clone().into_bytes();
        bad[3] = if bad[3] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            verify(
                &keys,
                &clock,
                300,
                4,
                std::str::from_utf8(&bad).unwrap(),
                &nonce
            ),
            Err(PowError::Invalid)
        );
        assert_eq!(
            verify(&keys, &clock, 300, 4, "short", &nonce),
            Err(PowError::Invalid)
        );
        clock.advance_secs(301);
        assert_eq!(
            verify(&keys, &clock, 300, 4, &c, &nonce),
            Err(PowError::Expired)
        );
    }
}
