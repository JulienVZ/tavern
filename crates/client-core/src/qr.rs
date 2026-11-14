// SPDX-License-Identifier: AGPL-3.0-or-later

//! QR codes, generated locally.
//!
//! Used to show the TOTP enrolment link to an authenticator app. The code is
//! computed on this device: the secret it carries is never sent to a third
//! party to be rendered.

use qrcode::{Color, EcLevel, QrCode};
use serde::Serialize;

use crate::error::ClientError;

/// Longest text accepted. An `otpauth://` link is well under this.
const MAX_TEXT_LEN: usize = 512;

/// A QR code as a square grid of modules, without the quiet zone.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct QrMatrix {
    /// Number of modules per side.
    pub size: usize,
    /// One string per row, `1` for a dark module and `0` for a light one.
    pub rows: Vec<String>,
}

// The matrix encodes a secret; printing it would be printing the secret.
impl std::fmt::Debug for QrMatrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QrMatrix({0}x{0}, <redacted>)", self.size)
    }
}

/// Encodes `text` as a QR code with medium error correction.
pub fn encode(text: &str) -> Result<QrMatrix, ClientError> {
    if text.is_empty() || text.len() > MAX_TEXT_LEN {
        return Err(ClientError::ServerError);
    }
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|_| ClientError::ServerError)?;
    let size = code.width();
    let rows = code
        .to_colors()
        .chunks(size)
        .map(|row| {
            row.iter()
                .map(|c| if *c == Color::Dark { '1' } else { '0' })
                .collect()
        })
        .collect();
    Ok(QrMatrix { size, rows })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str =
        "otpauth://totp/Tavern:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Tavern";

    #[test]
    fn the_matrix_is_square_and_binary() {
        let matrix = encode(LINK).unwrap();

        assert_eq!(matrix.rows.len(), matrix.size);
        assert!(matrix.rows.iter().all(|row| row.len() == matrix.size));
        assert!(
            matrix
                .rows
                .iter()
                .all(|row| row.bytes().all(|b| b == b'0' || b == b'1'))
        );
        // Version 1 is 21 modules wide and versions grow by 4.
        assert_eq!((matrix.size - 21) % 4, 0);
    }

    #[test]
    fn the_three_finder_patterns_are_present() {
        let matrix = encode(LINK).unwrap();
        let n = matrix.size;
        let dark = |row: usize, column: usize| matrix.rows[row].as_bytes()[column] == b'1';

        // Each finder pattern is a 7x7 square with a dark border and a dark
        // 3x3 centre, in three corners.
        for (top, left) in [(0, 0), (0, n - 7), (n - 7, 0)] {
            for i in 0..7 {
                assert!(
                    dark(top, left + i) && dark(top + 6, left + i),
                    "border at {top},{left}"
                );
                assert!(
                    dark(top + i, left) && dark(top + i, left + 6),
                    "border at {top},{left}"
                );
            }
            assert!(!dark(top + 1, left + 1) && dark(top + 3, left + 3));
        }
        // The fourth corner has none.
        assert!(!(0..7).all(|i| dark(n - 1, n - 1 - i)));
    }

    #[test]
    fn encoding_is_deterministic_and_depends_on_the_text() {
        assert_eq!(encode(LINK).unwrap(), encode(LINK).unwrap());
        assert_ne!(
            encode(LINK).unwrap(),
            encode(&LINK.replace("alice", "bobby")).unwrap()
        );
    }

    #[test]
    fn empty_and_oversized_text_is_refused() {
        assert!(encode("").is_err());
        assert!(encode(&"x".repeat(MAX_TEXT_LEN + 1)).is_err());
    }

    #[test]
    fn debug_output_does_not_reveal_the_modules() {
        let debug = format!("{:?}", encode(LINK).unwrap());

        assert!(debug.contains("redacted"));
        assert!(!debug.contains("0101") && !debug.contains("1010"));
    }
}
