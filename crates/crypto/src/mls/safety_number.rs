// SPDX-License-Identifier: AGPL-3.0-or-later

//! Safety numbers (ADR 0019, section 10): what two users compare to check
//! that each has the other's account identity key (AIK).
//!
//! For each user, `h = SHA-512("tavern safety number v1" || 0x00 || AIK ||
//! user id)`, then 5,199 more times `h = SHA-512(h || AIK)`: 5,200 hashes,
//! to slow down the search for a key whose number looks alike. The first 30
//! bytes of `h`, in six blocks of 5, each read as a big-endian integer modulo
//! 100,000, give 30 digits. The safety number is the two halves, the user
//! with the smaller id first: 60 digits, shown as 12 groups of 5.
//!
//! Devices do not enter it: they are certified by the AIK, so a new device
//! changes nothing. Nor do passwords: the AIK derives from the root secret,
//! which a password change or a recovery keeps.

use sha2::{Digest, Sha512};

use crate::identity::{ID_LEN, IdentityPublicKey, PUBLIC_KEY_LEN};

const LABEL: &[u8] = b"tavern safety number v1";
/// Hashes per half.
pub const ITERATIONS: usize = 5200;
/// Digits of a safety number.
pub const DIGITS: usize = 60;
/// Version byte of the QR code payload.
const QR_VERSION: u8 = 1;
/// Length of the QR code payload.
pub const QR_LEN: usize = 1 + 2 * PUBLIC_KEY_LEN;

/// One side of a conversation.
#[derive(Debug, Clone, Copy)]
pub struct Party<'a> {
    /// The account.
    pub user_id: &'a [u8; ID_LEN],
    /// Its account identity key, as this device knows it.
    pub identity_key: &'a IdentityPublicKey,
}

/// A safety number: 60 decimal digits.
#[derive(Clone, PartialEq, Eq)]
pub struct SafetyNumber(String);

impl SafetyNumber {
    /// The 60 digits, without spaces.
    pub fn digits(&self) -> &str {
        &self.0
    }

    /// The 12 groups of 5 digits, in display order.
    pub fn groups(&self) -> Vec<&str> {
        (0..DIGITS / 5)
            .map(|group| &self.0[group * 5..group * 5 + 5])
            .collect()
    }
}

impl std::fmt::Display for SafetyNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.groups().join(" "))
    }
}

impl std::fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SafetyNumber({self})")
    }
}

fn half(party: &Party<'_>) -> String {
    let key = party.identity_key.to_bytes();
    let mut hash = Sha512::new()
        .chain_update(LABEL)
        .chain_update([0])
        .chain_update(key)
        .chain_update(party.user_id)
        .finalize();
    for _ in 1..ITERATIONS {
        hash = Sha512::new()
            .chain_update(hash)
            .chain_update(key)
            .finalize();
    }
    let mut digits = String::with_capacity(DIGITS / 2);
    let (blocks, _) = hash[..30].as_chunks::<5>();
    for block in blocks {
        let value = block
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        digits.push_str(&format!("{:05}", value % 100_000));
    }
    digits
}

fn ordered<'a>(a: Party<'a>, b: Party<'a>) -> (Party<'a>, Party<'a>) {
    if a.user_id <= b.user_id {
        (a, b)
    } else {
        (b, a)
    }
}

/// The safety number of two users. The same whichever side computes it.
pub fn safety_number(a: Party<'_>, b: Party<'_>) -> SafetyNumber {
    let (first, second) = ordered(a, b);
    SafetyNumber(half(&first) + &half(&second))
}

/// What the QR code holds: a version byte and the two AIKs, the user with the
/// smaller id first. Scanning it compares the keys themselves.
pub fn qr_payload(a: Party<'_>, b: Party<'_>) -> [u8; QR_LEN] {
    let (first, second) = ordered(a, b);
    let mut out = [0u8; QR_LEN];
    out[0] = QR_VERSION;
    out[1..1 + PUBLIC_KEY_LEN].copy_from_slice(&first.identity_key.to_bytes());
    out[1 + PUBLIC_KEY_LEN..].copy_from_slice(&second.identity_key.to_bytes());
    out
}

/// Whether a scanned QR code matches the keys this device holds for the two
/// users. A different version, length or key does not match.
pub fn qr_matches(scanned: &[u8], a: Party<'_>, b: Party<'_>) -> bool {
    scanned == qr_payload(a, b).as_slice()
}
