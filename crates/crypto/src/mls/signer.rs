// SPDX-License-Identifier: AGPL-3.0-or-later

//! The keys that sign MLS messages.
//!
//! These signers sign MLS content only: RFC 9420's `SignContent`, which
//! starts with the length of its label (a one-byte variable-length integer,
//! below 64) followed by `"MLS 1.0 "`. Anything else is refused, so that a
//! signer handed to other code cannot be used to sign, say, a session proof
//! (whose signing input starts with `tavern …`). Signing other content stays
//! inside this crate.

use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;

use crate::identity::{DeviceKey, ExternalSenderKey};

const MLS_LABEL_PREFIX: &[u8] = b"MLS 1.0 ";

/// Whether `payload` is an MLS `SignContent`: a label length below 64 (one
/// byte), at least the prefix long and within the payload, then the prefix.
fn is_mls_sign_content(payload: &[u8]) -> bool {
    let Some((&length, rest)) = payload.split_first() else {
        return false;
    };
    let length = usize::from(length);
    length < 0x40
        && length >= MLS_LABEL_PREFIX.len()
        && rest.len() >= length
        && rest.starts_with(MLS_LABEL_PREFIX)
}

/// A device's key as its MLS signature key (ADR 0002): it signs the device's
/// leaf, its KeyPackages, commits and messages.
#[derive(Debug, Clone, Copy)]
pub struct DeviceSigner<'a>(&'a DeviceKey);

impl<'a> DeviceSigner<'a> {
    /// The MLS signer of a device key.
    pub fn new(key: &'a DeviceKey) -> Self {
        Self(key)
    }
}

impl Signer for DeviceSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        if !is_mls_sign_content(payload) {
            return Err(SignerError::SigningError);
        }
        Ok(self.0.sign_mls(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// The instance's external sender key: it signs the server's `Remove`
/// proposals, and nothing else (ADR 0019, section 6).
#[derive(Debug, Clone, Copy)]
pub struct ServerSigner<'a>(&'a ExternalSenderKey);

impl<'a> ServerSigner<'a> {
    /// The MLS signer of the external sender key.
    pub fn new(key: &'a ExternalSenderKey) -> Self {
        Self(key)
    }
}

impl Signer for ServerSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        if !is_mls_sign_content(payload) {
            return Err(SignerError::SigningError);
        }
        Ok(self.0.sign_mls(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests panic on failure")]

    use super::*;

    #[test]
    fn only_mls_content_is_signed() {
        let device = DeviceKey::generate();
        let server = ExternalSenderKey::generate();
        let signers: [&dyn Signer; 2] = [&DeviceSigner::new(&device), &ServerSigner::new(&server)];

        let mut mls = vec![19];
        mls.extend_from_slice(b"MLS 1.0 LeafNodeTBS");
        mls.extend_from_slice(&[3, 1, 2, 3]);
        for signer in signers {
            assert_eq!(signer.sign(&mls).unwrap().len(), 64);
            for refused in [
                &b""[..],
                b"tavern device session v1\0",
                b"\x13MLS 1.1 LeafNodeTBS",
                b"\x40MLS 1.0 LeafNodeTBS",
                b"\x07MLS 1.0",
                b"\x30MLS 1.0 short",
            ] {
                assert!(signer.sign(refused).is_err(), "{refused:?}");
            }
        }
    }
}
