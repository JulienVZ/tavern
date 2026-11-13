// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-size secrets that are erased from memory when dropped.

use std::fmt;

use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// `N` secret bytes, zeroised on drop.
///
/// The `Debug` output never contains the bytes, so a secret cannot leak
/// through a log line or a panic message. There is no `Display`, `Clone`,
/// `PartialEq` or serialisation: access is explicit through [`Secret::expose`].
pub struct Secret<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> Secret<N> {
    /// Takes ownership of `bytes`.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Draws `N` bytes from the operating system's random generator.
    pub fn random() -> Self {
        let mut bytes = Zeroizing::new([0u8; N]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// Copies a slice of exactly `N` bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut out = Zeroizing::new([0u8; N]);
        if bytes.len() != N {
            return None;
        }
        out.copy_from_slice(bytes);
        Some(Self(out))
    }

    /// The secret bytes. Keep the borrow short and never log it.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Compares two secrets in constant time.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_the_bytes() {
        let secret = Secret::new([0xAB; 32]);
        let debug = format!("{secret:?}");

        assert_eq!(debug, "Secret<32>(<redacted>)");
        assert!(!debug.to_lowercase().contains("ab"));
        assert!(!debug.contains("171"));
    }

    #[test]
    fn random_secrets_differ() {
        assert!(!Secret::<32>::random().ct_eq(&Secret::<32>::random()));
    }

    #[test]
    fn from_slice_checks_the_length() {
        assert!(Secret::<4>::from_slice(&[1, 2, 3]).is_none());
        assert!(Secret::<4>::from_slice(&[1, 2, 3, 4, 5]).is_none());
        let secret = Secret::<4>::from_slice(&[1, 2, 3, 4]).unwrap();
        assert_eq!(secret.expose(), &[1, 2, 3, 4]);
        assert!(secret.ct_eq(&Secret::new([1, 2, 3, 4])));
    }
}
