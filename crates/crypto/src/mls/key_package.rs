// SPDX-License-Identifier: AGPL-3.0-or-later

//! KeyPackages (ADR 0019, section 3): each device keeps 20 one-time packages
//! and one last-resort package on the server, valid 90 days.
//!
//! A package goes three ways: built by its device ([`build`]), checked by the
//! server when uploaded ([`validate_upload`]), and checked by the device that
//! claimed it before it adds anyone ([`validate_claimed`]). Only a
//! [`ClaimedKeyPackage`] can be added to a group.

use openmls::prelude::tls_codec::{DeserializeBytes, Serialize as _};
use openmls::prelude::{CredentialWithKey, KeyPackage, KeyPackageIn, Lifetime, ProtocolVersion};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

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

/// Builds a KeyPackage of this device. Its private parts go straight to the
/// provider's storage; only the public package, to upload, is returned.
pub fn build<P: OpenMlsProvider>(
    provider: &P,
    signer: &DeviceSigner<'_>,
    credential: CredentialWithKey,
    last_resort: bool,
) -> Result<KeyPackage, MlsError> {
    let builder = KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(LIFETIME_SECONDS))
        .leaf_node_capabilities(capabilities());
    let builder = if last_resort {
        builder.mark_as_last_resort()
    } else {
        builder
    };
    let bundle = builder
        .build(CIPHERSUITE, provider, signer, credential)
        .map_err(library)?;
    Ok(bundle.key_package().clone())
}

/// The bytes to upload.
pub fn to_bytes(key_package: &KeyPackage) -> Result<Vec<u8>, MlsError> {
    key_package.tls_serialize_detached().map_err(library)
}

/// Why a KeyPackage was refused.
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
    /// The credential is another device's than expected.
    #[error("the KeyPackage belongs to another device")]
    WrongDevice,
    /// A last-resort package in a one-time slot, or the reverse.
    #[error("the last-resort flag does not match")]
    LastResortMismatch,
}

/// The checks common to an upload and a claim.
fn validate(
    crypto: &RustCrypto,
    bytes: &[u8],
    roster: &impl Roster,
    expected: VerifiedLeaf,
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
    let verified = verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), roster)?;
    if verified != expected {
        return Err(KeyPackageError::WrongDevice);
    }
    Ok(key_package)
}

/// The device uploading KeyPackages, as the server knows it.
#[derive(Debug, Clone)]
pub struct Uploader {
    /// Its account.
    pub user_id: [u8; ID_LEN],
    /// The device.
    pub device_id: [u8; ID_LEN],
    /// The account's identity key, from the server's database.
    pub identity_key: IdentityPublicKey,
    /// The key the device enrolled with (`devices.signature_key`).
    pub signature_key: Vec<u8>,
    /// The certificate it enrolled with (`devices.certificate`).
    pub certificate: Vec<u8>,
}

impl Roster for Uploader {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        (*user_id == self.user_id).then_some(self.identity_key)
    }

    /// A package carries the device itself (ADR 0019, section 2): the very
    /// key and certificate it enrolled with, which a group would require of
    /// its leaf anyway. Another device's package is refused next, as
    /// [`KeyPackageError::WrongDevice`].
    fn check_device(
        &self,
        device: &VerifiedLeaf,
        signature_key: &[u8],
        certificate: &[u8],
    ) -> Result<(), LeafError> {
        let uploader = device.user_id == self.user_id && device.device_id == self.device_id;
        if uploader
            && (signature_key != self.signature_key.as_slice()
                || certificate != self.certificate.as_slice())
        {
            return Err(LeafError::NotEnrolled);
        }
        Ok(())
    }
}

/// What the server stores of a KeyPackage it accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedKeyPackage {
    /// Its `KeyPackageRef`, the hash that names it.
    pub reference: Vec<u8>,
    /// The encryption key of its leaf (TLS-encoded): the key the device's
    /// leaf has in a group this package added it to, until the device
    /// updates its leaf. It tells the server which package a group's first
    /// commit added.
    pub leaf_key: Vec<u8>,
    /// The end of its lifetime, in seconds since the Unix epoch.
    pub not_after: u64,
}

/// Validates an uploaded KeyPackage on the server: OpenMLS's checks
/// (signature, distinct keys, lifetime now valid), Tavern's ciphersuite, a
/// lifetime of at most 90 days, the uploader's own device certificate, the
/// key and certificate the device enrolled with, and the last-resort flag
/// of the slot it is uploaded to.
pub fn validate_upload(
    bytes: &[u8],
    uploader: &Uploader,
    last_resort_slot: bool,
) -> Result<UploadedKeyPackage, KeyPackageError> {
    let crypto = RustCrypto::default();
    let expected = VerifiedLeaf {
        user_id: uploader.user_id,
        device_id: uploader.device_id,
    };
    let key_package = validate(&crypto, bytes, uploader, expected)?;
    if key_package.last_resort() != last_resort_slot {
        return Err(KeyPackageError::LastResortMismatch);
    }
    let reference = key_package
        .hash_ref(&crypto)
        .map_err(|error| KeyPackageError::Invalid(error.to_string()))?;
    Ok(UploadedKeyPackage {
        reference: reference.as_slice().to_vec(),
        leaf_key: key_package
            .leaf_node()
            .encryption_key()
            .tls_serialize_detached()
            .map_err(|error| KeyPackageError::Invalid(error.to_string()))?,
        not_after: key_package.life_time().not_after(),
    })
}

/// A KeyPackage claimed from the server and checked by this device: the only
/// kind a group accepts to add.
#[derive(Debug, Clone)]
pub struct ClaimedKeyPackage(KeyPackage);

impl ClaimedKeyPackage {
    /// The device it belongs to.
    pub fn device(&self) -> Option<VerifiedLeaf> {
        super::credential::name_leaf(self.0.leaf_node().credential())
    }

    pub(crate) fn key_package(&self) -> &KeyPackage {
        &self.0
    }
}

/// Checks a KeyPackage claimed for the device `device` (the server says which
/// device each package is for): the same checks as an upload, against the
/// identity key this device trusts for that user (the roster).
pub fn validate_claimed(
    bytes: &[u8],
    device: VerifiedLeaf,
    roster: &impl Roster,
) -> Result<ClaimedKeyPackage, KeyPackageError> {
    validate(&RustCrypto::default(), bytes, roster, device).map(ClaimedKeyPackage)
}
