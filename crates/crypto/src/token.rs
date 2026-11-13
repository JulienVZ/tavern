// SPDX-License-Identifier: AGPL-3.0-or-later

//! Random tokens and codes, and the hashes under which the server stores them.
//!
//! Session tokens, enrolment tokens and invitation codes are long random
//! values, so a plain SHA-256 is enough to store them: there is nothing to
//! guess. Passwords never go through this module.

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{CryptoError, encoding};

/// Length of a session or enrolment token, in bytes.
pub const TOKEN_LEN: usize = 32;
/// Length of an invitation code or a TOTP recovery code before encoding, in bytes.
pub const CODE_LEN: usize = 16;
/// Length of a stored hash, in bytes.
pub const HASH_LEN: usize = 32;

/// Fills an array from the operating system's random generator.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// SHA-256 of a token or code: what the server stores instead of the value.
pub fn hash(token: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(token).into()
}

/// Compares two byte strings in constant time.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// A code meant to be read and typed by a person: an invitation code or a
/// TOTP recovery code. 128 random bits, shown as Crockford base32 in groups.
pub struct HumanCode(Zeroizing<[u8; CODE_LEN]>);

impl HumanCode {
    /// Draws a new random code.
    pub fn generate() -> Self {
        Self(Zeroizing::new(random_bytes()))
    }

    /// Parses a code as typed by a person (case, spaces and hyphens are ignored).
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        encoding::decode(text).map(Self)
    }

    /// The code as shown to the person, e.g. `7QK2-…`.
    pub fn display(&self) -> Zeroizing<String> {
        encoding::encode_grouped(self.0.as_slice())
    }

    /// The hash under which the server stores the code.
    pub fn hash(&self) -> [u8; HASH_LEN] {
        hash(self.0.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_the_sha256_test_vector() {
        // SHA-256("abc"), FIPS 180-2.
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash(b"abc"), expected);
    }

    #[test]
    fn codes_survive_being_retyped() {
        let code = HumanCode::generate();
        let shown = code.display();
        let retyped = shown.to_lowercase().replace('-', " ");

        assert_eq!(shown.len(), 26 + 6);
        assert_eq!(HumanCode::parse(&retyped).unwrap().hash(), code.hash());
    }

    #[test]
    fn different_codes_have_different_hashes() {
        assert_ne!(HumanCode::generate().hash(), HumanCode::generate().hash());
        assert!(HumanCode::parse("not a code").is_err());
    }

    #[test]
    fn constant_time_eq_compares_content_and_length() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
