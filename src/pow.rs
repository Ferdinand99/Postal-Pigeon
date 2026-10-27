//! Registration proof of work (docs/design.md section 6.1).
//!
//! A challenge is stateless: eight bytes of issue time, one byte of difficulty,
//! sixteen random bytes and a truncated HMAC over all of it, URL-safe base64.
//! The difficulty is the one asked for when the challenge was issued (it rises
//! with recent registration volume), and the HMAC keeps a client from lowering
//! it. The relay remembers only the ids of challenges it has accepted, until
//! they expire, so each works once. The client finds a `nonce` such that
//! `SHA-256(challenge ‖ nonce)` (both as their UTF-8 text) starts with
//! `difficulty` zero bits.

use crate::clock::Clock;
use crate::crypto::{Keys, ct_eq, sha256};
use crate::util::{b64, b64_decode, leading_zero_bits, random_bytes};

const MAC_LEN: usize = 16;
const RAW_LEN: usize = 8 + 1 + 16 + MAC_LEN;
/// A challenge from the future (clock skew after a restart) is accepted up to this much.
const SKEW_SECS: i64 = 60;
/// Longest nonce accepted.
pub const MAX_NONCE_LEN: usize = 64;

/// A new challenge asking for `difficulty` bits, and the Unix time (seconds)
/// it expires.
pub fn issue(keys: &Keys, clock: &Clock, ttl_secs: i64, difficulty: u32) -> (String, i64) {
    let issued = clock.now_secs();
    let mut body = Vec::with_capacity(RAW_LEN);
    body.extend_from_slice(&issued.to_be_bytes());
    body.push(difficulty.min(255) as u8);
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

/// A challenge whose MAC and age are right, before its proof is looked at.
#[derive(Debug, PartialEq, Eq)]
pub struct Checked {
    /// The challenge's random id, which the caller records as used.
    pub id: [u8; 16],
    /// The difficulty it was issued with.
    pub difficulty: u32,
}

/// Checks that `challenge` is one this relay issued and is still fresh.
pub fn check(
    keys: &Keys,
    clock: &Clock,
    ttl_secs: i64,
    challenge: &str,
) -> Result<Checked, PowError> {
    if challenge.len() > 128 {
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
    Ok(Checked {
        id: body[9..25].try_into().expect("16 bytes"),
        difficulty: u32::from(body[8]),
    })
}

/// Checks a nonce against a challenge's difficulty.
pub fn check_proof(challenge: &str, nonce: &str, difficulty: u32) -> Result<(), PowError> {
    if nonce.is_empty() || nonce.len() > MAX_NONCE_LEN || !nonce.is_ascii() {
        return Err(PowError::Invalid);
    }
    let digest = sha256(&[challenge.as_bytes(), nonce.as_bytes()].concat());
    if leading_zero_bits(&digest) < difficulty {
        return Err(PowError::BadProof);
    }
    Ok(())
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
        let (c, exp) = issue(&keys, &clock, 300, 8);
        assert_eq!(exp, clock.now_secs() + 300);
        let checked = check(&keys, &clock, 300, &c).unwrap();
        assert_eq!(checked.difficulty, 8);
        let nonce = solve(&c, 8);
        assert!(check_proof(&c, &nonce, checked.difficulty).is_ok());
        // Stricter difficulty than the nonce was found for (almost surely) fails.
        assert_eq!(check_proof(&c, &nonce, 32), Err(PowError::BadProof));
        assert_eq!(check_proof(&c, "", 1), Err(PowError::Invalid));
    }

    #[test]
    fn the_difficulty_cannot_be_lowered() {
        let keys = Keys::ephemeral();
        let clock = Clock::new();
        let (c, _) = issue(&keys, &clock, 300, 20);
        let mut raw = b64_decode(&c).unwrap();
        raw[8] = 1;
        assert_eq!(
            check(&keys, &clock, 300, &b64(&raw)),
            Err(PowError::Invalid)
        );
    }

    #[test]
    fn rejects_foreign_tampered_and_expired() {
        let keys = Keys::ephemeral();
        let clock = Clock::new();
        let (c, _) = issue(&keys, &clock, 300, 4);
        let other = Keys::ephemeral();
        assert_eq!(check(&other, &clock, 300, &c), Err(PowError::Invalid));
        let mut bad = c.clone().into_bytes();
        bad[3] = if bad[3] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            check(&keys, &clock, 300, std::str::from_utf8(&bad).unwrap()),
            Err(PowError::Invalid)
        );
        assert_eq!(check(&keys, &clock, 300, "short"), Err(PowError::Invalid));
        clock.advance_secs(301);
        assert_eq!(check(&keys, &clock, 300, &c), Err(PowError::Expired));
    }
}
