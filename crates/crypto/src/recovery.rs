// SPDX-License-Identifier: AGPL-3.0-or-later

//! The recovery key: 256 random bits shown once to the user at registration.
//!
//! It opens the "recovery" wrapped copy of the account identity key, which
//! lets its holder set a new password without losing the identity. The server
//! never sees it. Generating a new one (after re-authentication) replaces the
//! wrapped copy, so the previous key stops working.

use zeroize::Zeroizing;

use crate::secret::Secret;
use crate::{CryptoError, encoding};

/// Length of a recovery key, in bytes.
pub const RECOVERY_KEY_LEN: usize = 32;

/// A recovery key.
#[derive(Debug)]
pub struct RecoveryKey(Secret<RECOVERY_KEY_LEN>);

impl RecoveryKey {
    /// Draws a new recovery key from the operating system's random generator.
    pub fn generate() -> Self {
        Self(Secret::random())
    }

    /// Parses a recovery key as typed by the user. Case, spaces and hyphens
    /// are ignored; `O` reads as `0`, `I` and `L` as `1`.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let bytes = encoding::decode::<RECOVERY_KEY_LEN>(text)?;
        Ok(Self(Secret::new(*bytes)))
    }

    /// The key as shown to the user: 52 characters in 13 groups of four.
    pub fn display(&self) -> Zeroizing<String> {
        encoding::encode_grouped(self.0.expose())
    }

    pub(crate) fn secret(&self) -> &Secret<RECOVERY_KEY_LEN> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_has_thirteen_groups_of_four() {
        let shown = RecoveryKey::generate().display();
        let groups: Vec<&str> = shown.split('-').collect();

        assert_eq!(groups.len(), 13);
        assert!(groups.iter().all(|group| group.len() == 4));
        assert!(
            shown
                .chars()
                .all(|c| c == '-' || "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c))
        );
    }

    #[test]
    fn a_retyped_key_is_the_same_key() {
        let key = RecoveryKey::generate();
        let retyped = key.display().to_lowercase().replace('-', "  ");

        assert!(
            RecoveryKey::parse(&retyped)
                .unwrap()
                .secret()
                .ct_eq(key.secret())
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let shown = RecoveryKey::generate().display();

        assert!(RecoveryKey::parse(&shown[..shown.len() - 1]).is_err());
        assert!(RecoveryKey::parse("").is_err());
        assert!(RecoveryKey::parse(&format!("{}-0000", shown.as_str())).is_err());
    }

    #[test]
    fn debug_output_is_redacted() {
        let key = RecoveryKey::generate();
        let debug = format!("{key:?}");

        assert!(debug.contains("redacted"));
        assert!(!debug.contains(key.display().as_str()));
    }
}
