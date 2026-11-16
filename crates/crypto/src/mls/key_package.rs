// SPDX-License-Identifier: AGPL-3.0-or-later

//! KeyPackages (ADR 0019, section 3): each device keeps 20 one-time packages
//! and one last-resort package on the server, valid 90 days.

use openmls::prelude::tls_codec::{DeserializeBytes, Serialize as _};
use openmls::prelude::{
    CredentialWithKey, KeyPackage, KeyPackageBundle, KeyPackageIn, Lifetime, ProtocolVersion,
};
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;

use super::credential::{LeafError, Roster, VerifiedLeaf, verify_leaf};
use super::{CIPHERSUITE, DeviceSigner, MlsError, capabilities, library};
use crate::identity::{ID_LEN, IdentityPublicKey};

/// One-time KeyPackages a device keeps on the server.
pub const ONE_TIME_COUNT: usize = 20;
/// Below this many, the server asks for more (`KeyPackagesLow`).
pub const LOW_WATERMARK: usize = 10;
/// How long a KeyPackage is valid.
pub const LIFETIME_SECONDS: u64 = 90 * 24 * 3600;
/// The last-resort KeyPackage is replaced after this many days, and when used.
pub const LAST_RESORT_ROTATION_DAYS: u64 = 30;
/// OpenMLS starts a lifetime one hour in the past for skewed clocks; a
/// little more is tolerated for packages built by other devices.
const LIFETIME_TOLERANCE_SECONDS: u64 = 2 * 3600;
/// Largest KeyPackage accepted (`protocol.md`, limits).
pub const MAX_SIZE: usize = 4 * 1024;

/// Builds a KeyPackage of this device. Its private parts go to the
/// provider's storage; the returned package is to be uploaded.
pub fn build<P: OpenMlsProvider>(
    provider: &P,
    signer: &DeviceSigner<'_>,
    credential: CredentialWithKey,
    last_resort: bool,
) -> Result<KeyPackageBundle, MlsError> {
    let builder = KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(LIFETIME_SECONDS))
        .leaf_node_capabilities(capabilities());
    let builder = if last_resort {
        builder.mark_as_last_resort()
    } else {
        builder
    };
    builder
        .build(CIPHERSUITE, provider, signer, credential)
        .map_err(library)
}

/// The bytes to upload.
pub fn to_bytes(key_package: &KeyPackage) -> Result<Vec<u8>, MlsError> {
    key_package.tls_serialize_detached().map_err(library)
}

/// Why an uploaded KeyPackage was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyPackageError {
    /// Not a KeyPackage, or larger than [`MAX_SIZE`].
    #[error("malformed KeyPackage")]
    Malformed,
    /// Another ciphersuite than Tavern's.
    #[error("the KeyPackage uses another ciphersuite")]
    WrongCiphersuite,
    /// OpenMLS's checks failed: signature, keys, expired lifetime.
    #[error("invalid KeyPackage: {0}")]
    Invalid(String),
    /// Valid for longer than Tavern's 90 days.
    #[error("the KeyPackage is valid for too long")]
    LifetimeTooLong,
    /// The leaf's credential is not acceptable.
    #[error("the KeyPackage's credential: {0}")]
    Leaf(#[from] LeafError),
    /// The credential is another device's than the uploader's.
    #[error("the KeyPackage belongs to another device")]
    WrongDevice,
    /// A last-resort package in a one-time slot, or the reverse.
    #[error("the last-resort flag does not match")]
    LastResortMismatch,
}

/// The device uploading KeyPackages, as the server knows it.
#[derive(Debug, Clone, Copy)]
pub struct Uploader {
    /// Its account.
    pub user_id: [u8; ID_LEN],
    /// The device.
    pub device_id: [u8; ID_LEN],
    /// The account's identity key, from the server's database.
    pub identity_key: IdentityPublicKey,
}

impl Roster for Uploader {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        (*user_id == self.user_id).then_some(self.identity_key)
    }
}

/// Validates an uploaded KeyPackage on the server: OpenMLS's checks
/// (signature, distinct keys, lifetime now valid), Tavern's ciphersuite, a
/// lifetime of at most 90 days, the uploader's own device certificate, and
/// the last-resort flag of the slot it is uploaded to.
pub fn validate_upload(
    crypto: &impl OpenMlsCrypto,
    bytes: &[u8],
    uploader: &Uploader,
    last_resort_slot: bool,
) -> Result<KeyPackage, KeyPackageError> {
    if bytes.len() > MAX_SIZE {
        return Err(KeyPackageError::Malformed);
    }
    let (incoming, rest) =
        KeyPackageIn::tls_deserialize_bytes(bytes).map_err(|_| KeyPackageError::Malformed)?;
    if !rest.is_empty() {
        return Err(KeyPackageError::Malformed);
    }
    let key_package = incoming
        .validate(crypto, ProtocolVersion::Mls10)
        .map_err(|error| KeyPackageError::Invalid(error.to_string()))?;
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(KeyPackageError::WrongCiphersuite);
    }
    let lifetime = key_package.life_time();
    if lifetime.not_after().saturating_sub(lifetime.not_before())
        > LIFETIME_SECONDS + LIFETIME_TOLERANCE_SECONDS
    {
        return Err(KeyPackageError::LifetimeTooLong);
    }
    let leaf = key_package.leaf_node();
    let VerifiedLeaf { user_id, device_id } =
        verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), uploader)?;
    if user_id != uploader.user_id || device_id != uploader.device_id {
        return Err(KeyPackageError::WrongDevice);
    }
    if key_package.last_resort() != last_resort_slot {
        return Err(KeyPackageError::LastResortMismatch);
    }
    Ok(key_package)
}
