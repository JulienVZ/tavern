// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account handles and their canonical form.
//!
//! A handle is the public identifier of an account and the OPAQUE credential
//! identifier, so both sides must agree on its exact bytes. The rules are
//! deliberately strict:
//!
//! - ASCII only: `a`–`z`, `0`–`9`, `_` and `.`;
//! - 2 to 32 characters;
//! - no leading or trailing `.`, no `..`.
//!
//! There is exactly one normalisation step, [`Handle::canonicalize`], which
//! lower-cases ASCII letters. Everything else is rejected rather than
//! repaired: no trimming, no Unicode case folding, no compatibility mapping.
//! A look-alike such as a Cyrillic `а` or a full-width `Ａ` is therefore an
//! error, never a different spelling of an existing handle.
//!
//! The client canonicalises what the user typed. The server accepts canonical
//! handles only ([`Handle::parse_canonical`]) and never lower-cases on its
//! own. Both use this module.
//!
//! A handle cannot be changed in v1, because the password record is bound to
//! it.

use std::fmt;

/// Shortest accepted handle, in characters.
pub const MIN_HANDLE_LEN: usize = 2;
/// Longest accepted handle, in characters.
pub const MAX_HANDLE_LEN: usize = 32;

/// A handle in canonical form.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(String);

/// Why a string is not an acceptable handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandleError {
    /// Fewer than [`MIN_HANDLE_LEN`] characters.
    #[error("the handle is too short")]
    TooShort,
    /// More than [`MAX_HANDLE_LEN`] characters.
    #[error("the handle is too long")]
    TooLong,
    /// A character outside `a`–`z`, `0`–`9`, `_`, `.` (after lower-casing).
    #[error("the handle contains a character that is not allowed")]
    InvalidCharacter,
    /// A leading or trailing `.`, or two consecutive dots.
    #[error("the handle has a misplaced dot")]
    MisplacedDot,
    /// The handle contains upper-case letters where the canonical form is required.
    #[error("the handle is not in canonical form")]
    NotCanonical,
}

impl Handle {
    /// Canonicalises what a user typed: ASCII letters are lower-cased, and the
    /// result must satisfy every rule. Nothing else is altered.
    pub fn canonicalize(input: &str) -> Result<Self, HandleError> {
        // Only ASCII letters are touched; any other character is checked as is.
        Self::validate(input.to_ascii_lowercase())
    }

    /// Accepts a handle only if it is already canonical. Used by the server
    /// for every handle received from the network.
    pub fn parse_canonical(input: &str) -> Result<Self, HandleError> {
        if input.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(HandleError::NotCanonical);
        }
        Self::validate(input.to_owned())
    }

    fn validate(candidate: String) -> Result<Self, HandleError> {
        // Characters are checked before the length so that multi-byte input
        // is reported as an invalid character, whatever its byte length.
        if !candidate
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.'))
        {
            return Err(HandleError::InvalidCharacter);
        }
        // From here on the string is ASCII: bytes and characters coincide.
        if candidate.len() < MIN_HANDLE_LEN {
            return Err(HandleError::TooShort);
        }
        if candidate.len() > MAX_HANDLE_LEN {
            return Err(HandleError::TooLong);
        }
        if candidate.starts_with('.') || candidate.ends_with('.') || candidate.contains("..") {
            return Err(HandleError::MisplacedDot);
        }
        Ok(Self(candidate))
    }

    /// The canonical handle.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The canonical handle as bytes: the OPAQUE credential identifier.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_handles_are_kept_as_is() {
        for input in [
            "ab",
            "julien",
            "j.doe",
            "a_b",
            "user_42",
            "0x",
            "a.b.c",
            &"a".repeat(32),
        ] {
            let handle = Handle::canonicalize(input).unwrap();
            assert_eq!(handle.as_str(), input);
            assert_eq!(Handle::parse_canonical(input).unwrap(), handle);
        }
    }

    #[test]
    fn ascii_upper_case_is_lowered_by_the_client_and_refused_by_the_server() {
        assert_eq!(Handle::canonicalize("Julien").unwrap().as_str(), "julien");
        assert_eq!(
            Handle::canonicalize("J.DOE_42").unwrap().as_str(),
            "j.doe_42"
        );
        assert_eq!(
            Handle::parse_canonical("Julien"),
            Err(HandleError::NotCanonical)
        );
    }

    #[test]
    fn whitespace_is_never_trimmed_or_accepted() {
        for input in [
            " julien",
            "julien ",
            "ju lien",
            "julien\n",
            "\tjulien",
            "julien\u{a0}",
        ] {
            assert_eq!(
                Handle::canonicalize(input),
                Err(HandleError::InvalidCharacter),
                "{input:?}"
            );
            assert_eq!(
                Handle::parse_canonical(input),
                Err(HandleError::InvalidCharacter)
            );
        }
    }

    #[test]
    fn unicode_look_alikes_are_rejected() {
        for input in [
            "juli\u{0435}n",  // Cyrillic small ie
            "\u{0430}dmin",   // Cyrillic small a
            "\u{ff41}dmin",   // full-width a
            "admin\u{200b}",  // zero-width space
            "adm\u{0131}n",   // dotless i
            "ju\u{0301}lien", // combining acute accent
            "julién",         // precomposed e acute
            "JULI\u{212a}",   // Kelvin sign, lower-cases to k under Unicode rules
            "stra\u{df}e",    // sharp s
            "\u{1d5ba}dmin",  // mathematical sans-serif a
            "ad\u{00ad}min",  // soft hyphen
            "admin\u{202e}",  // right-to-left override
        ] {
            assert_eq!(
                Handle::canonicalize(input),
                Err(HandleError::InvalidCharacter),
                "{input:?}"
            );
            // The server may report upper-case letters first; either way it refuses.
            assert!(Handle::parse_canonical(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn other_ascii_characters_are_rejected() {
        for input in [
            "ju-lien", "ju@lien", "ju/lien", "a+b", "a:b", "ab\0", "a'b", "a\"b", "<ab>",
        ] {
            assert_eq!(
                Handle::canonicalize(input),
                Err(HandleError::InvalidCharacter),
                "{input:?}"
            );
        }
    }

    #[test]
    fn length_is_bounded() {
        assert_eq!(Handle::canonicalize(""), Err(HandleError::TooShort));
        assert_eq!(Handle::canonicalize("a"), Err(HandleError::TooShort));
        assert_eq!(
            Handle::canonicalize(&"a".repeat(33)),
            Err(HandleError::TooLong)
        );
        assert!(Handle::canonicalize(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn dots_cannot_lead_trail_or_repeat() {
        for input in [".ab", "ab.", "a..b", ".."] {
            assert_eq!(
                Handle::canonicalize(input),
                Err(HandleError::MisplacedDot),
                "{input}"
            );
        }
    }

    #[test]
    fn canonicalisation_is_idempotent() {
        let once = Handle::canonicalize("J.Doe_42").unwrap();
        let twice = Handle::canonicalize(once.as_str()).unwrap();
        assert_eq!(once, twice);
        assert_eq!(Handle::parse_canonical(once.as_str()).unwrap(), once);
    }
}
