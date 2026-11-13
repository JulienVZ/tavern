// SPDX-License-Identifier: AGPL-3.0-or-later

//! Human-friendly encoding of keys and codes: Crockford base32.
//!
//! The alphabet has no `I`, `L`, `O` or `U`. Decoding is forgiving about what
//! people do when copying by hand: case is ignored, `O` reads as `0`, `I` and
//! `L` read as `1`, and spaces and hyphens are skipped.

use std::sync::LazyLock;

use data_encoding::{Encoding, Specification};
use zeroize::Zeroizing;

use crate::CryptoError;

const GROUP_LEN: usize = 4;

static CROCKFORD: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    spec.translate.from.push_str("abcdefghjkmnpqrstvwxyzOoIiLl");
    spec.translate.to.push_str("ABCDEFGHJKMNPQRSTVWXYZ001111");
    spec.ignore.push_str("- ");
    #[expect(
        clippy::expect_used,
        reason = "the specification is a constant; `encodes_and_decodes` exercises it"
    )]
    spec.encoding()
        .expect("the Crockford base32 specification is valid")
});

/// Encodes `bytes` in groups of four characters separated by hyphens.
pub(crate) fn encode_grouped(bytes: &[u8]) -> Zeroizing<String> {
    let flat = Zeroizing::new(CROCKFORD.encode(bytes));
    let mut out = Zeroizing::new(String::with_capacity(flat.len() + flat.len() / GROUP_LEN));
    for (index, character) in flat.chars().enumerate() {
        if index > 0 && index % GROUP_LEN == 0 {
            out.push('-');
        }
        out.push(character);
    }
    out
}

/// Decodes text produced by [`encode_grouped`], however the user retyped it.
pub(crate) fn decode<const N: usize>(text: &str) -> Result<Zeroizing<[u8; N]>, CryptoError> {
    let decoded = Zeroizing::new(
        CROCKFORD
            .decode(text.as_bytes())
            .map_err(|_| CryptoError::InvalidEncoding)?,
    );
    let mut out = Zeroizing::new([0u8; N]);
    if decoded.len() != N {
        return Err(CryptoError::InvalidEncoding);
    }
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn encodes_and_decodes() {
        let bytes = [
            0u8, 1, 2, 3, 250, 251, 252, 253, 254, 255, 16, 32, 64, 128, 7, 9,
        ];
        let text = encode_grouped(&bytes);

        assert_eq!(text.as_str(), "000G-40ZT-ZFYF-VZQZ-20G4-1007-14");
        assert_eq!(*decode::<16>(&text).unwrap(), bytes);
    }

    #[test]
    fn decoding_forgives_case_separators_and_look_alikes() {
        let bytes = [
            0u8, 1, 2, 3, 250, 251, 252, 253, 254, 255, 16, 32, 64, 128, 7, 9,
        ];

        for retyped in [
            "000g40ztzfyfvzqz20g4100714",
            "000G 40ZT ZFYF VZQZ 20G4 1007 14",
            "OOOG-4OZT-ZFYF-VZQZ-2OG4-lOO7-I4",
        ] {
            assert_eq!(*decode::<16>(retyped).unwrap(), bytes, "{retyped}");
        }
    }

    #[test]
    fn decoding_rejects_wrong_length_and_foreign_characters() {
        assert_eq!(
            decode::<16>("000G-40ZT").unwrap_err(),
            CryptoError::InvalidEncoding
        );
        assert_eq!(decode::<16>("").unwrap_err(), CryptoError::InvalidEncoding);
        assert_eq!(
            decode::<16>("000G-40ZT-ZFYF-VZQZ-20G4-1007-1U").unwrap_err(),
            CryptoError::InvalidEncoding
        );
        assert_eq!(
            decode::<16>("000G-40ZT-ZFYF-VZQZ-20G4-1007-14!").unwrap_err(),
            CryptoError::InvalidEncoding
        );
    }

    proptest! {
        #[test]
        fn round_trips_any_32_bytes(bytes in any::<[u8; 32]>()) {
            let text = encode_grouped(&bytes);
            prop_assert_eq!(text.len(), 52 + 12);
            prop_assert_eq!(*decode::<32>(&text).unwrap(), bytes);
            prop_assert_eq!(*decode::<32>(&text.to_lowercase()).unwrap(), bytes);
        }
    }
}
