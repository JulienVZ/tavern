// SPDX-License-Identifier: AGPL-3.0-or-later

//! Leaves and their credentials (ADR 0002; ADR 0019, section 2).
//!
//! A leaf's credential is a basic credential whose identity is the device
//! certificate: user id, device id and device key, signed by the account
//! identity key (AIK). The leaf's signature key is the device key itself.
//! A leaf is accepted only if its certificate verifies under the AIK that the
//! caller trusts for that user, and certifies that very signature key.

use std::collections::HashSet;

use openmls::prelude::{Credential, CredentialType, CredentialWithKey};

use crate::CryptoError;
use crate::identity::{DevicePublicKey, ID_LEN, IdentityPublicKey, certificate_claimed_ids};

/// Who may be in a conversation, and which identity key to trust for each.
///
/// On a client: the participants of the conversation and their pinned keys
/// (ADR 0019, section 10). On the server: the participants and
/// `users.identity_key`.
pub trait Roster {
    /// The account identity key trusted for `user_id`, if that user takes
    /// part in the conversation; `None` otherwise.
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey>;
}

/// A leaf whose certificate was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifiedLeaf {
    /// The account.
    pub user_id: [u8; ID_LEN],
    /// The device.
    pub device_id: [u8; ID_LEN],
}

/// Why a leaf is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LeafError {
    /// Not a basic credential.
    #[error("the credential is not a Tavern device certificate")]
    NotBasic,
    /// The certificate cannot be decoded.
    #[error("the device certificate cannot be decoded")]
    Malformed,
    /// The certificate's user does not take part in the conversation.
    #[error("the device belongs to a user outside the conversation")]
    NotParticipant,
    /// The certificate has a version this build does not know.
    #[error("the device certificate has an unsupported version")]
    UnsupportedVersion,
    /// The certificate does not verify under the identity key trusted for
    /// its user: forged, or signed by another key (a changed identity).
    #[error("the device certificate does not verify under the trusted identity key")]
    Untrusted,
    /// The leaf's signature key is not the certified device key.
    #[error("the leaf's key is not the certified device key")]
    KeyMismatch,
    /// Two leaves belong to the same device (same user and device ids).
    #[error("two leaves belong to the same device")]
    DuplicateDevice,
    /// A leaf was replaced by the leaf of another device.
    #[error("a leaf was replaced by another device")]
    DeviceChanged,
}

/// The credential of this device, with its signature key.
pub fn for_device(certificate: &[u8], device_key: &DevicePublicKey) -> CredentialWithKey {
    CredentialWithKey {
        credential: openmls::prelude::BasicCredential::new(certificate.to_vec()).into(),
        signature_key: device_key.to_bytes().to_vec().into(),
    }
}

/// Checks one leaf: its credential, and its signature key.
pub fn verify_leaf(
    credential: &Credential,
    signature_key: &[u8],
    roster: &impl Roster,
) -> Result<VerifiedLeaf, LeafError> {
    if credential.credential_type() != CredentialType::Basic {
        return Err(LeafError::NotBasic);
    }
    let certificate = credential.serialized_content();
    let (claimed_user, _) =
        certificate_claimed_ids(certificate).map_err(|_| LeafError::Malformed)?;
    let identity = roster
        .identity_key(&claimed_user)
        .ok_or(LeafError::NotParticipant)?;
    let verified =
        identity
            .verify_device_certificate(certificate)
            .map_err(|error| match error {
                CryptoError::UnsupportedVersion => LeafError::UnsupportedVersion,
                CryptoError::InvalidSignature => LeafError::Untrusted,
                _ => LeafError::Malformed,
            })?;
    if verified.user_id != claimed_user {
        return Err(LeafError::Malformed);
    }
    if verified.device_key.to_bytes().as_slice() != signature_key {
        return Err(LeafError::KeyMismatch);
    }
    Ok(VerifiedLeaf {
        user_id: verified.user_id,
        device_id: verified.device_id,
    })
}

/// Checks every leaf of a group, and that no device (user id and device id)
/// has two leaves.
pub fn verify_members<'a>(
    leaves: impl IntoIterator<Item = (&'a Credential, &'a [u8])>,
    roster: &impl Roster,
) -> Result<Vec<VerifiedLeaf>, LeafError> {
    let mut seen = HashSet::new();
    let mut verified = Vec::new();
    for (credential, signature_key) in leaves {
        let leaf = verify_leaf(credential, signature_key, roster)?;
        if !seen.insert(leaf) {
            return Err(LeafError::DuplicateDevice);
        }
        verified.push(leaf);
    }
    Ok(verified)
}

/// Names a leaf that was verified when it joined, without verifying again.
pub(crate) fn name_leaf(credential: &Credential) -> Option<VerifiedLeaf> {
    let (user_id, device_id) = certificate_claimed_ids(credential.serialized_content()).ok()?;
    Some(VerifiedLeaf { user_id, device_id })
}
