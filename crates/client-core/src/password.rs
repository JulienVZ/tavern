// SPDX-License-Identifier: AGPL-3.0-or-later

//! Password strength, checked on the client.
//!
//! The server never sees a password, so it cannot enforce anything about it.
//! The requirement matters more than usual here: the password also protects
//! the account identity key (see `docs/adr/0003-opaque-authentication.md`).
//!
//! A password is accepted when it has at least [`MIN_LENGTH`] characters and
//! a zxcvbn score of [`MIN_SCORE`] or more. The handle and display name count
//! as known words, so a password built from them scores low.

use serde::Serialize;

/// Minimum number of characters.
pub const MIN_LENGTH: usize = 12;
/// Minimum zxcvbn score, out of 4.
pub const MIN_SCORE: u8 = 3;
/// Passwords longer than this are refused rather than truncated.
pub const MAX_LENGTH: usize = 256;

/// Why a password is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordIssue {
    /// Fewer than [`MIN_LENGTH`] characters.
    TooShort,
    /// More than [`MAX_LENGTH`] characters.
    TooLong,
    /// Long enough, but too easy to guess.
    TooGuessable,
}

/// The assessment shown by the strength meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PasswordStrength {
    /// zxcvbn score, 0 (trivial) to 4 (strong).
    pub score: u8,
    /// Number of characters.
    pub length: usize,
    /// Why the password is refused, or `None` when it is acceptable.
    pub issue: Option<PasswordIssue>,
}

impl PasswordStrength {
    /// Whether the password may be used.
    pub fn is_acceptable(&self) -> bool {
        self.issue.is_none()
    }
}

/// Assesses a password. `context` lists words an attacker would try first:
/// the handle and the display name.
pub fn assess(password: &str, context: &[&str]) -> PasswordStrength {
    let length = password.chars().count();
    if length > MAX_LENGTH {
        return PasswordStrength {
            score: 0,
            length,
            issue: Some(PasswordIssue::TooLong),
        };
    }
    let score = u8::from(zxcvbn::zxcvbn(password, context).score());
    let issue = if length < MIN_LENGTH {
        Some(PasswordIssue::TooShort)
    } else if score < MIN_SCORE {
        Some(PasswordIssue::TooGuessable)
    } else {
        None
    };
    PasswordStrength {
        score,
        length,
        issue,
    }
}

/// Returns the issue that makes a password unusable, if any.
pub fn check(password: &str, context: &[&str]) -> Result<(), PasswordIssue> {
    assess(password, context).issue.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_passwords_are_refused_whatever_their_score() {
        assert_eq!(check("", &[]), Err(PasswordIssue::TooShort));
        assert_eq!(check("Tr0ub4dor&3", &[]), Err(PasswordIssue::TooShort));
        // Eleven random-looking characters: strong for zxcvbn, still too short.
        assert_eq!(check("xK9#mQ2$vL7", &[]), Err(PasswordIssue::TooShort));
    }

    #[test]
    fn long_but_guessable_passwords_are_refused() {
        for password in [
            "passwordpassword",
            "123456789012345",
            "qwertyuiopasdfgh",
            "aaaaaaaaaaaaaaaa",
            "letmeinletmein1",
        ] {
            assert_eq!(
                check(password, &[]),
                Err(PasswordIssue::TooGuessable),
                "{password}"
            );
        }
    }

    #[test]
    fn passwords_built_from_the_handle_are_refused() {
        assert_eq!(
            check("aliceexample1", &["aliceexample", "Julien"]),
            Err(PasswordIssue::TooGuessable)
        );
    }

    #[test]
    fn strong_passphrases_are_accepted() {
        for password in [
            "correct horse battery staple",
            "xK9#mQ2$vL7!pR4z",
            "tournesol-vexant-42-brume",
        ] {
            let strength = assess(password, &["alice"]);
            assert!(strength.is_acceptable(), "{password}: {strength:?}");
            assert!(strength.score >= MIN_SCORE);
        }
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        // Twelve characters, more than twelve bytes.
        let strength = assess("éèàùçâêîôûäë", &[]);
        assert_eq!(strength.length, 12);
        assert_ne!(strength.issue, Some(PasswordIssue::TooShort));
    }

    #[test]
    fn absurdly_long_passwords_are_refused() {
        assert_eq!(check(&"a1B!".repeat(100), &[]), Err(PasswordIssue::TooLong));
    }
}
