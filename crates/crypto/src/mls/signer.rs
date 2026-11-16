// SPDX-License-Identifier: AGPL-3.0-or-later

//! The keys that sign MLS messages.

use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;

use crate::identity::{DeviceKey, ExternalSenderKey};

/// A device's key as its MLS signature key (ADR 0002): it signs the device's
/// leaf, its KeyPackages, commits and messages.
#[derive(Debug, Clone, Copy)]
pub struct DeviceSigner<'a>(pub &'a DeviceKey);

impl Signer for DeviceSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign_mls(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// The instance's external sender key: it signs the server's `Remove`
/// proposals, and nothing else (ADR 0019, section 6).
#[derive(Debug, Clone, Copy)]
pub struct ServerSigner<'a>(pub &'a ExternalSenderKey);

impl Signer for ServerSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign_mls(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
