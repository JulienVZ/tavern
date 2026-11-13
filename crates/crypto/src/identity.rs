// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account identity, device keys and the signatures built on them.
//!
//! # Keys
//!
//! - The **account identity key** (AIK) is an Ed25519 key pair generated at
//!   registration. Its public half is the account's identity: contacts compare
//!   it as a safety number. Its private half exists in clear only in the
//!   memory of a client, for the time needed to certify a device or authorise
//!   a credential change, and is erased when dropped.
//! - Two **wrapped copies** of the AIK private key are stored by the server:
//!   one under a key derived from the OPAQUE export key (so from the
//!   password), one under a key derived from the recovery key. The server can
//!   open neither.
//! - Each device has its own Ed25519 **device key**, certified by the AIK.
//!
//! # Wrapped key format (version 1, 73 bytes)
//!
//! ```text
//! 0x01 || nonce (24 bytes) || XChaCha20-Poly1305(seed, 32 bytes) || tag (16 bytes)
//! ```
//!
//! The wrapping key is `HKDF-SHA512(secret, info = label)`, with a different
//! label for each kind of copy. The associated data binds the ciphertext to
//! its kind and to the AIK public key, so the server cannot swap a copy
//! between accounts or between the two kinds.
//!
//! # Signatures
//!
//! Every signature covers a domain separation label followed by
//! length-prefixed fields ([`signing_input`]), so a signature made for one
//! purpose can never be replayed for another.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use prost::Message;
use rand::rngs::OsRng;
use sha2::Sha512;
use tavern_protocol::handle::Handle;
use tavern_protocol::identity::v1 as proto;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::opaque::ExportKey;
use crate::recovery::RecoveryKey;
use crate::secret::Secret;
use crate::token::random_bytes;

/// Length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Length of an account or device identifier (a UUID), in bytes.
pub const ID_LEN: usize = 16;
/// Length of a server challenge, in bytes.
pub const CHALLENGE_LEN: usize = 32;
/// Length of a wrapped account identity key, in bytes.
pub const WRAPPED_KEY_LEN: usize = 1 + NONCE_LEN + SEED_LEN + TAG_LEN;

const SEED_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const WRAPPED_KEY_VERSION: u8 = 1;
const CERTIFICATE_VERSION: u32 = 1;

const LABEL_WRAP_PASSWORD: &[u8] = b"tavern aik wrap v1 password";
const LABEL_WRAP_RECOVERY: &[u8] = b"tavern aik wrap v1 recovery";
const LABEL_WRAP_AAD: &[u8] = b"tavern aik wrapped v1";
const LABEL_DECOY: &[u8] = b"tavern aik decoy v1";
const LABEL_CERTIFICATE: &[u8] = b"tavern device certificate v1";
const LABEL_SESSION: &[u8] = b"tavern device session v1";
const LABEL_CREDENTIAL_UPDATE: &[u8] = b"tavern credential update v1";

/// Builds the bytes that get signed: the label, a zero byte, then each field
/// preceded by its length as a 32-bit big-endian integer.
///
/// The label cannot contain a zero byte and every field is length-prefixed,
/// so two different (label, fields) inputs never produce the same bytes.
fn signing_input(label: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        label.len() + 1 + fields.iter().map(|field| 4 + field.len()).sum::<usize>(),
    );
    out.extend_from_slice(label);
    out.push(0);
    for field in fields {
        // Fields are keys, identifiers and short protocol messages. A field
        // longer than 4 GiB cannot occur; saturating keeps this total.
        out.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

fn verify(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let signature = Signature::from_slice(signature).map_err(|_| CryptoError::InvalidSignature)?;
    // `verify_strict` also rejects small-order keys and non-canonical signatures.
    key.verify_strict(message, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Parses an Ed25519 public key. Rejects encodings that are not curve points
/// and small-order points, for which signatures prove nothing.
fn parse_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<VerifyingKey, CryptoError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidMessage)?;
    if key.is_weak() {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(key)
}

/// The public half of an account identity key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentityPublicKey(VerifyingKey);

impl IdentityPublicKey {
    /// Parses a public key, rejecting values that are not valid curve points.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: &[u8; PUBLIC_KEY_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidMessage)?;
        parse_public_key(bytes).map(Self)
    }

    /// The key as bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verifies a device certificate issued by this account and returns its
    /// content. The signature is checked over the received bytes before they
    /// are decoded.
    pub fn verify_device_certificate(
        &self,
        certificate: &[u8],
    ) -> Result<DeviceCertificate, CryptoError> {
        let envelope = proto::DeviceCertificate::decode(certificate)
            .map_err(|_| CryptoError::InvalidMessage)?;
        verify(
            &self.0,
            &signing_input(LABEL_CERTIFICATE, &[&envelope.payload]),
            &envelope.signature,
        )?;

        let payload = proto::DeviceCertificatePayload::decode(envelope.payload.as_slice())
            .map_err(|_| CryptoError::InvalidMessage)?;
        if payload.version != CERTIFICATE_VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }
        let device_key = DevicePublicKey::from_bytes(&payload.signature_key)?;
        Ok(DeviceCertificate {
            user_id: payload
                .user_id
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidMessage)?,
            device_id: payload
                .device_id
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidMessage)?,
            device_key,
            issued_at_ms: payload.issued_at_ms,
        })
    }

    /// Verifies that the holder of this account's identity key authorised a
    /// credential change.
    pub fn verify_credential_update(
        &self,
        update: &CredentialUpdate<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        verify(&self.0, &update.signing_input(), signature)
    }
}

impl std::fmt::Debug for IdentityPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityPublicKey({:02x?})", self.0.to_bytes())
    }
}

/// Which wrapped copy of the account identity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapKind {
    /// The copy opened with the password (through the OPAQUE export key).
    Password,
    /// The copy opened with the recovery key.
    Recovery,
}

impl WrapKind {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Password => b"password",
            Self::Recovery => b"recovery",
        }
    }
}

/// A key that wraps the account identity key.
#[derive(Debug)]
pub struct WrappingKey {
    key: Secret<32>,
    kind: WrapKind,
}

impl WrappingKey {
    /// Derives the wrapping key of the "password" copy.
    pub fn from_export_key(export_key: &ExportKey) -> Result<Self, CryptoError> {
        Self::derive(
            export_key.secret().expose(),
            LABEL_WRAP_PASSWORD,
            WrapKind::Password,
        )
    }

    /// Derives the wrapping key of the "recovery" copy.
    pub fn from_recovery_key(recovery_key: &RecoveryKey) -> Result<Self, CryptoError> {
        Self::derive(
            recovery_key.secret().expose(),
            LABEL_WRAP_RECOVERY,
            WrapKind::Recovery,
        )
    }

    fn derive(secret: &[u8], label: &[u8], kind: WrapKind) -> Result<Self, CryptoError> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha512>::new(None, secret)
            .expand(label, key.as_mut())
            .map_err(|_| CryptoError::Internal)?;
        Ok(Self {
            key: Secret::new(*key),
            kind,
        })
    }

    /// Which copy this key opens.
    pub fn kind(&self) -> WrapKind {
        self.kind
    }
}

fn wrap_aad(kind: WrapKind, public: &IdentityPublicKey) -> Vec<u8> {
    signing_input(LABEL_WRAP_AAD, &[kind.tag(), &public.to_bytes()])
}

/// An account identity key, private half included. Erased when dropped.
pub struct AccountIdentityKey(SigningKey);

impl AccountIdentityKey {
    /// Generates a new account identity key.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// The public half.
    pub fn public(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.0.verifying_key())
    }

    /// Encrypts the private half under `key`. The result is what the server
    /// stores; it can be opened only with the same key, for the same account
    /// and the same kind of copy.
    pub fn wrap(&self, key: &WrappingKey) -> Result<Vec<u8>, CryptoError> {
        let nonce: [u8; NONCE_LEN] = random_bytes();
        let seed = Zeroizing::new(self.0.to_bytes());
        let ciphertext = XChaCha20Poly1305::new(key.key.expose().into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: seed.as_slice(),
                    aad: &wrap_aad(key.kind, &self.public()),
                },
            )
            .map_err(|_| CryptoError::Internal)?;

        let mut out = Vec::with_capacity(WRAPPED_KEY_LEN);
        out.push(WRAPPED_KEY_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens a wrapped copy.
    ///
    /// `expected` is the account's public identity key as published by the
    /// server. Opening fails if the key is wrong, if the copy belongs to
    /// another account or is of the other kind, or if a byte was altered.
    pub fn unwrap(
        wrapped: &[u8],
        key: &WrappingKey,
        expected: &IdentityPublicKey,
    ) -> Result<Self, CryptoError> {
        if wrapped.len() != WRAPPED_KEY_LEN {
            return Err(CryptoError::InvalidWrappedKey);
        }
        let (version, rest) = wrapped.split_at(1);
        if version != [WRAPPED_KEY_VERSION] {
            return Err(CryptoError::UnsupportedVersion);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);

        let seed = Zeroizing::new(
            XChaCha20Poly1305::new(key.key.expose().into())
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &wrap_aad(key.kind, expected),
                    },
                )
                .map_err(|_| CryptoError::InvalidWrappedKey)?,
        );
        let seed: &[u8; SEED_LEN] = seed
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidWrappedKey)?;

        let identity = Self(SigningKey::from_bytes(seed));
        if identity.public() != *expected {
            return Err(CryptoError::InvalidWrappedKey);
        }
        Ok(identity)
    }

    /// Issues the certificate that binds a device key to this account.
    pub fn certify_device(
        &self,
        user_id: &[u8; ID_LEN],
        device_id: &[u8; ID_LEN],
        device_key: &DevicePublicKey,
        issued_at_ms: u64,
    ) -> Vec<u8> {
        let payload = proto::DeviceCertificatePayload {
            version: CERTIFICATE_VERSION,
            user_id: user_id.to_vec(),
            device_id: device_id.to_vec(),
            signature_key: device_key.to_bytes().to_vec(),
            issued_at_ms,
        }
        .encode_to_vec();
        let signature = self.0.sign(&signing_input(LABEL_CERTIFICATE, &[&payload]));

        proto::DeviceCertificate {
            payload,
            signature: signature.to_bytes().to_vec(),
        }
        .encode_to_vec()
    }

    /// Authorises a credential change with this identity.
    pub fn sign_credential_update(&self, update: &CredentialUpdate<'_>) -> [u8; SIGNATURE_LEN] {
        self.0.sign(&update.signing_input()).to_bytes()
    }
}

impl std::fmt::Debug for AccountIdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountIdentityKey(<redacted>)")
    }
}

/// A stand-in for a wrapped "recovery" copy, returned by the server when the
/// handle is unknown so that the answer does not reveal which handles exist.
///
/// It has the format and length of a real copy and is a deterministic
/// function of the instance's handle-privacy key and the handle, so asking
/// twice gives the same bytes, as it would for a real account. It cannot be
/// opened by any key.
pub fn decoy_wrapped_key(
    handle_privacy_key: &Secret<32>,
    handle: &Handle,
) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; WRAPPED_KEY_LEN];
    out[0] = WRAPPED_KEY_VERSION;
    Hkdf::<Sha512>::new(None, handle_privacy_key.expose())
        .expand_multi_info(&[LABEL_DECOY, &[0], handle.as_bytes()], &mut out[1..])
        .map_err(|_| CryptoError::Internal)?;
    Ok(out)
}

/// The public key shown with a decoy wrapped copy.
///
/// It is a valid Ed25519 public key derived from the handle-privacy key and
/// the handle, so that it parses like a real one and is stable per handle.
/// Nobody holds the matching private key in a usable form.
pub fn decoy_identity_key(
    handle_privacy_key: &Secret<32>,
    handle: &Handle,
) -> Result<IdentityPublicKey, CryptoError> {
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    Hkdf::<Sha512>::new(None, handle_privacy_key.expose())
        .expand_multi_info(&[LABEL_DECOY, &[1], handle.as_bytes()], seed.as_mut())
        .map_err(|_| CryptoError::Internal)?;
    Ok(IdentityPublicKey(
        SigningKey::from_bytes(&seed).verifying_key(),
    ))
}

/// The instance's MLS external sender key: a dedicated Ed25519 key with which
/// the server signs `Remove` proposals (from milestone M2). It is used for
/// nothing else. At M1 only its public half is published.
pub struct ExternalSenderKey(SigningKey);

impl ExternalSenderKey {
    /// Generates a new key.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Restores the key from its seed.
    pub fn from_seed(seed: &Secret<SEED_LEN>) -> Self {
        Self(SigningKey::from_bytes(seed.expose()))
    }

    /// The seed, as stored in the instance configuration. Secret.
    pub fn seed(&self) -> Secret<SEED_LEN> {
        Secret::new(self.0.to_bytes())
    }

    /// The public half, published by `GET /version` and the gateway.
    pub fn public_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.verifying_key().to_bytes()
    }
}

impl std::fmt::Debug for ExternalSenderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExternalSenderKey(<redacted>)")
    }
}

/// What a credential change is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialUpdatePurpose {
    /// Setting a new password with the recovery key.
    Recovery,
    /// Changing the password from an authenticated session.
    PasswordChange,
    /// Replacing the recovery key.
    RecoveryKeyRotation,
}

impl CredentialUpdatePurpose {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Recovery => b"recovery",
            Self::PasswordChange => b"password-change",
            Self::RecoveryKeyRotation => b"recovery-key-rotation",
        }
    }
}

/// A credential change, as signed by the account identity key.
///
/// The signature covers the purpose, the server's single-use challenge, the
/// handle and every new value, so a signature cannot be replayed, moved to
/// another account, or attached to different values.
#[derive(Debug, Clone, Copy)]
pub struct CredentialUpdate<'a> {
    /// What the change is for.
    pub purpose: CredentialUpdatePurpose,
    /// The single-use challenge issued by the server for this change.
    pub challenge: &'a [u8; CHALLENGE_LEN],
    /// The account concerned.
    pub handle: &'a Handle,
    /// The new OPAQUE `RegistrationUpload`, or empty when the password does not change.
    pub opaque_upload: &'a [u8],
    /// The new "password" wrapped copy, or empty when it does not change.
    pub wrapped_password_copy: &'a [u8],
    /// The new "recovery" wrapped copy, or empty when it does not change.
    pub wrapped_recovery_copy: &'a [u8],
}

impl CredentialUpdate<'_> {
    fn signing_input(&self) -> Vec<u8> {
        signing_input(
            LABEL_CREDENTIAL_UPDATE,
            &[
                self.purpose.tag(),
                self.challenge,
                self.handle.as_bytes(),
                self.opaque_upload,
                self.wrapped_password_copy,
                self.wrapped_recovery_copy,
            ],
        )
    }
}

/// The content of a verified device certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceCertificate {
    /// Account the device belongs to.
    pub user_id: [u8; ID_LEN],
    /// Device identifier.
    pub device_id: [u8; ID_LEN],
    /// Public key of the device.
    pub device_key: DevicePublicKey,
    /// When the certificate was issued, in milliseconds since the Unix epoch.
    pub issued_at_ms: u64,
}

/// The public half of a device key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DevicePublicKey(VerifyingKey);

impl DevicePublicKey {
    /// Parses a public key, rejecting values that are not valid curve points.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: &[u8; PUBLIC_KEY_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidMessage)?;
        parse_public_key(bytes).map(Self)
    }

    /// The key as bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verifies the proof a device gives to reopen a session.
    pub fn verify_session_proof(
        &self,
        challenge: &SessionChallenge<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        verify(&self.0, &challenge.signing_input(), signature)
    }
}

impl std::fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DevicePublicKey({:02x?})", self.0.to_bytes())
    }
}

/// What a device signs to reopen a session: the server's single-use nonce,
/// bound to the account and the device.
#[derive(Debug, Clone, Copy)]
pub struct SessionChallenge<'a> {
    /// Single-use nonce issued by the server after a successful login.
    pub nonce: &'a [u8; CHALLENGE_LEN],
    /// Account the session is for.
    pub user_id: &'a [u8; ID_LEN],
    /// Device asking for the session.
    pub device_id: &'a [u8; ID_LEN],
}

impl SessionChallenge<'_> {
    fn signing_input(&self) -> Vec<u8> {
        signing_input(LABEL_SESSION, &[self.nonce, self.user_id, self.device_id])
    }
}

/// A device key, private half included. Erased when dropped.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    /// Generates a new device key.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Restores a device key from its seed, as kept in the OS keychain.
    pub fn from_seed(seed: &Secret<SEED_LEN>) -> Self {
        Self(SigningKey::from_bytes(seed.expose()))
    }

    /// The seed to keep in the OS keychain.
    pub fn seed(&self) -> Secret<SEED_LEN> {
        Secret::new(self.0.to_bytes())
    }

    /// The public half.
    pub fn public(&self) -> DevicePublicKey {
        DevicePublicKey(self.0.verifying_key())
    }

    /// Proves possession of this device key to reopen a session.
    pub fn sign_session_proof(&self, challenge: &SessionChallenge<'_>) -> [u8; SIGNATURE_LEN] {
        self.0.sign(&challenge.signing_input()).to_bytes()
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const USER: [u8; ID_LEN] = [1; ID_LEN];
    const DEVICE: [u8; ID_LEN] = [2; ID_LEN];

    fn recovery_wrapping_key() -> (RecoveryKey, WrappingKey) {
        let recovery = RecoveryKey::generate();
        let key = WrappingKey::from_recovery_key(&recovery).unwrap();
        (recovery, key)
    }

    #[test]
    fn signing_input_is_unambiguous() {
        // The same bytes split differently must not collide.
        assert_ne!(
            signing_input(b"l", &[b"ab", b"c"]),
            signing_input(b"l", &[b"a", b"bc"])
        );
        assert_ne!(
            signing_input(b"l", &[b"ab"]),
            signing_input(b"l", &[b"ab", b""])
        );
        assert_ne!(signing_input(b"la", &[b"b"]), signing_input(b"l", &[b"ab"]));
        assert_eq!(
            signing_input(b"l", &[b"ab"]),
            [b'l', 0, 0, 0, 0, 2, b'a', b'b']
        );
    }

    #[test]
    fn a_wrapped_key_opens_with_the_same_key() {
        let identity = AccountIdentityKey::generate();
        let (_, key) = recovery_wrapping_key();

        let wrapped = identity.wrap(&key).unwrap();
        let opened = AccountIdentityKey::unwrap(&wrapped, &key, &identity.public()).unwrap();

        assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
        assert_eq!(wrapped[0], WRAPPED_KEY_VERSION);
        assert_eq!(opened.public(), identity.public());
    }

    #[test]
    fn wrapping_twice_gives_different_ciphertexts() {
        let identity = AccountIdentityKey::generate();
        let (_, key) = recovery_wrapping_key();

        assert_ne!(identity.wrap(&key).unwrap(), identity.wrap(&key).unwrap());
    }

    #[test]
    fn a_wrapped_key_does_not_open_with_another_key() {
        let identity = AccountIdentityKey::generate();
        let (_, key) = recovery_wrapping_key();
        let (_, other) = recovery_wrapping_key();
        let wrapped = identity.wrap(&key).unwrap();

        assert_eq!(
            AccountIdentityKey::unwrap(&wrapped, &other, &identity.public()).unwrap_err(),
            CryptoError::InvalidWrappedKey
        );
    }

    #[test]
    fn a_wrapped_key_cannot_be_moved_to_another_account() {
        let alice = AccountIdentityKey::generate();
        let mallory = AccountIdentityKey::generate();
        let (_, key) = recovery_wrapping_key();
        let wrapped = alice.wrap(&key).unwrap();

        assert_eq!(
            AccountIdentityKey::unwrap(&wrapped, &key, &mallory.public()).unwrap_err(),
            CryptoError::InvalidWrappedKey
        );
    }

    #[test]
    fn the_two_kinds_of_copies_are_not_interchangeable() {
        let identity = AccountIdentityKey::generate();
        let recovery = RecoveryKey::generate();
        let as_recovery = WrappingKey::from_recovery_key(&recovery).unwrap();
        // Same key bytes, declared as the other kind: the associated data differs.
        let as_password = WrappingKey {
            key: Secret::new(*as_recovery.key.expose()),
            kind: WrapKind::Password,
        };
        let wrapped = identity.wrap(&as_recovery).unwrap();

        assert_eq!(as_recovery.kind(), WrapKind::Recovery);
        assert_eq!(
            AccountIdentityKey::unwrap(&wrapped, &as_password, &identity.public()).unwrap_err(),
            CryptoError::InvalidWrappedKey
        );
    }

    #[test]
    fn every_altered_byte_is_detected() {
        let identity = AccountIdentityKey::generate();
        let (_, key) = recovery_wrapping_key();
        let wrapped = identity.wrap(&key).unwrap();

        for index in 0..wrapped.len() {
            let mut altered = wrapped.clone();
            altered[index] ^= 0x01;
            assert!(
                AccountIdentityKey::unwrap(&altered, &key, &identity.public()).is_err(),
                "byte {index}"
            );
        }
        assert!(AccountIdentityKey::unwrap(&wrapped[..72], &key, &identity.public()).is_err());
        assert!(AccountIdentityKey::unwrap(&[], &key, &identity.public()).is_err());
    }

    #[test]
    fn an_unknown_version_is_reported_as_such() {
        let identity = AccountIdentityKey::generate();
        let (_, key) = recovery_wrapping_key();
        let mut wrapped = identity.wrap(&key).unwrap();
        wrapped[0] = 2;

        assert_eq!(
            AccountIdentityKey::unwrap(&wrapped, &key, &identity.public()).unwrap_err(),
            CryptoError::UnsupportedVersion
        );
    }

    #[test]
    fn decoys_look_real_are_stable_and_never_open() {
        let privacy_key = Secret::<32>::random();
        let nobody = Handle::parse_canonical("nobody").unwrap();
        let someone = Handle::parse_canonical("someone").unwrap();

        let decoy = decoy_wrapped_key(&privacy_key, &nobody).unwrap();

        assert_eq!(decoy.len(), WRAPPED_KEY_LEN);
        assert_eq!(decoy[0], WRAPPED_KEY_VERSION);
        assert_eq!(decoy, decoy_wrapped_key(&privacy_key, &nobody).unwrap());
        assert_ne!(decoy, decoy_wrapped_key(&privacy_key, &someone).unwrap());
        assert_ne!(
            decoy,
            decoy_wrapped_key(&Secret::random(), &nobody).unwrap()
        );

        let identity = AccountIdentityKey::generate();
        let (_, key) = recovery_wrapping_key();
        assert_eq!(
            AccountIdentityKey::unwrap(&decoy, &key, &identity.public()).unwrap_err(),
            CryptoError::InvalidWrappedKey
        );
    }

    #[test]
    fn decoy_identity_keys_are_valid_and_stable() {
        let privacy_key = Secret::<32>::random();
        let nobody = Handle::parse_canonical("nobody").unwrap();
        let someone = Handle::parse_canonical("someone").unwrap();

        let decoy = decoy_identity_key(&privacy_key, &nobody).unwrap();

        assert_eq!(decoy, decoy_identity_key(&privacy_key, &nobody).unwrap());
        assert_ne!(decoy, decoy_identity_key(&privacy_key, &someone).unwrap());
        assert!(IdentityPublicKey::from_bytes(&decoy.to_bytes()).is_ok());
    }

    #[test]
    fn the_external_sender_key_survives_its_seed_round_trip() {
        let key = ExternalSenderKey::generate();
        let restored = ExternalSenderKey::from_seed(&key.seed());

        assert_eq!(restored.public_bytes(), key.public_bytes());
        assert_eq!(format!("{key:?}"), "ExternalSenderKey(<redacted>)");
    }

    #[test]
    fn a_device_certificate_verifies_and_exposes_its_content() {
        let identity = AccountIdentityKey::generate();
        let device = DeviceKey::generate();

        let certificate =
            identity.certify_device(&USER, &DEVICE, &device.public(), 1_700_000_000_000);
        let verified = identity
            .public()
            .verify_device_certificate(&certificate)
            .unwrap();

        assert_eq!(
            verified,
            DeviceCertificate {
                user_id: USER,
                device_id: DEVICE,
                device_key: device.public(),
                issued_at_ms: 1_700_000_000_000,
            }
        );
    }

    #[test]
    fn a_certificate_from_another_account_is_rejected() {
        let identity = AccountIdentityKey::generate();
        let other = AccountIdentityKey::generate();
        let certificate =
            identity.certify_device(&USER, &DEVICE, &DeviceKey::generate().public(), 0);

        assert_eq!(
            other
                .public()
                .verify_device_certificate(&certificate)
                .unwrap_err(),
            CryptoError::InvalidSignature
        );
    }

    #[test]
    fn an_altered_certificate_is_rejected() {
        let identity = AccountIdentityKey::generate();
        let certificate =
            identity.certify_device(&USER, &DEVICE, &DeviceKey::generate().public(), 7);

        for index in 0..certificate.len() {
            let mut altered = certificate.clone();
            altered[index] ^= 0x01;
            assert!(
                identity
                    .public()
                    .verify_device_certificate(&altered)
                    .is_err(),
                "byte {index}"
            );
        }
    }

    #[test]
    fn a_certificate_with_an_unknown_version_is_rejected() {
        let identity = AccountIdentityKey::generate();
        let payload = proto::DeviceCertificatePayload {
            version: 2,
            user_id: USER.to_vec(),
            device_id: DEVICE.to_vec(),
            signature_key: DeviceKey::generate().public().to_bytes().to_vec(),
            issued_at_ms: 0,
        }
        .encode_to_vec();
        let signature = identity
            .0
            .sign(&signing_input(LABEL_CERTIFICATE, &[&payload]));
        let certificate = proto::DeviceCertificate {
            payload,
            signature: signature.to_bytes().to_vec(),
        }
        .encode_to_vec();

        assert_eq!(
            identity
                .public()
                .verify_device_certificate(&certificate)
                .unwrap_err(),
            CryptoError::UnsupportedVersion
        );
    }

    #[test]
    fn a_session_proof_is_bound_to_nonce_account_and_device() {
        let device = DeviceKey::generate();
        let nonce = [9u8; CHALLENGE_LEN];
        let challenge = SessionChallenge {
            nonce: &nonce,
            user_id: &USER,
            device_id: &DEVICE,
        };
        let proof = device.sign_session_proof(&challenge);

        assert!(
            device
                .public()
                .verify_session_proof(&challenge, &proof)
                .is_ok()
        );

        let other_nonce = [8u8; CHALLENGE_LEN];
        for altered in [
            SessionChallenge {
                nonce: &other_nonce,
                ..challenge
            },
            SessionChallenge {
                user_id: &DEVICE,
                ..challenge
            },
            SessionChallenge {
                device_id: &USER,
                ..challenge
            },
        ] {
            assert_eq!(
                device
                    .public()
                    .verify_session_proof(&altered, &proof)
                    .unwrap_err(),
                CryptoError::InvalidSignature
            );
        }
        assert!(
            DeviceKey::generate()
                .public()
                .verify_session_proof(&challenge, &proof)
                .is_err()
        );
        assert!(
            device
                .public()
                .verify_session_proof(&challenge, &proof[..63])
                .is_err()
        );
    }

    #[test]
    fn a_device_key_survives_the_keychain_round_trip() {
        let device = DeviceKey::generate();
        let restored = DeviceKey::from_seed(&device.seed());

        assert_eq!(restored.public(), device.public());
    }

    #[test]
    fn a_credential_update_signature_covers_every_field() {
        let identity = AccountIdentityKey::generate();
        let alice = Handle::parse_canonical("alice").unwrap();
        let bob = Handle::parse_canonical("bob").unwrap();
        let challenge = [3u8; CHALLENGE_LEN];
        let update = CredentialUpdate {
            purpose: CredentialUpdatePurpose::Recovery,
            challenge: &challenge,
            handle: &alice,
            opaque_upload: b"upload",
            wrapped_password_copy: b"wrapped",
            wrapped_recovery_copy: b"",
        };
        let signature = identity.sign_credential_update(&update);

        assert!(
            identity
                .public()
                .verify_credential_update(&update, &signature)
                .is_ok()
        );

        let other_challenge = [4u8; CHALLENGE_LEN];
        for altered in [
            CredentialUpdate {
                purpose: CredentialUpdatePurpose::PasswordChange,
                ..update
            },
            CredentialUpdate {
                purpose: CredentialUpdatePurpose::RecoveryKeyRotation,
                ..update
            },
            CredentialUpdate {
                challenge: &other_challenge,
                ..update
            },
            CredentialUpdate {
                handle: &bob,
                ..update
            },
            CredentialUpdate {
                opaque_upload: b"uploae",
                ..update
            },
            CredentialUpdate {
                wrapped_password_copy: b"",
                ..update
            },
            CredentialUpdate {
                wrapped_recovery_copy: b"x",
                ..update
            },
            // Moving bytes from one field to the next must not verify.
            CredentialUpdate {
                opaque_upload: b"uploadw",
                wrapped_password_copy: b"rapped",
                ..update
            },
        ] {
            assert_eq!(
                identity
                    .public()
                    .verify_credential_update(&altered, &signature)
                    .unwrap_err(),
                CryptoError::InvalidSignature
            );
        }
        let stranger = AccountIdentityKey::generate();
        assert!(
            stranger
                .public()
                .verify_credential_update(&update, &signature)
                .is_err()
        );
    }

    #[test]
    fn invalid_public_keys_are_rejected() {
        assert!(IdentityPublicKey::from_bytes(&[0u8; 31]).is_err());
        assert!(DevicePublicKey::from_bytes(&[0u8; 33]).is_err());
        // Small-order points: the identity element and a point of order 4.
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        assert!(IdentityPublicKey::from_bytes(&identity_point).is_err());
        assert!(DevicePublicKey::from_bytes(&identity_point).is_err());
        assert!(IdentityPublicKey::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn debug_output_of_private_keys_is_redacted() {
        let identity = AccountIdentityKey::generate();
        let device = DeviceKey::generate();
        let (_, key) = recovery_wrapping_key();

        assert_eq!(format!("{identity:?}"), "AccountIdentityKey(<redacted>)");
        assert_eq!(format!("{device:?}"), "DeviceKey(<redacted>)");
        assert!(format!("{key:?}").contains("redacted"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn wrap_then_unwrap_round_trips(seed in any::<[u8; 32]>(), wrapping in any::<[u8; 32]>()) {
            let identity = AccountIdentityKey(SigningKey::from_bytes(&seed));
            let key = WrappingKey { key: Secret::new(wrapping), kind: WrapKind::Password };

            let wrapped = identity.wrap(&key).unwrap();
            let opened = AccountIdentityKey::unwrap(&wrapped, &key, &identity.public()).unwrap();

            prop_assert_eq!(opened.public(), identity.public());
        }

        #[test]
        fn arbitrary_bytes_never_verify_as_a_certificate(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let identity = AccountIdentityKey(SigningKey::from_bytes(&[5; 32]));
            prop_assert!(identity.public().verify_device_certificate(&bytes).is_err());
        }
    }
}

/// Known answers computed once and frozen. A failure here means a stored or
/// transmitted format changed: existing accounts would stop working.
#[cfg(test)]
mod frozen_vectors {
    use super::*;

    const IDENTITY_SEED: [u8; 32] = [7; 32];
    const IDENTITY_PUBLIC: &str =
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const RECOVERY_KEY: &str = "144G-J289-144G-J289-144G-J289-144G-J289-144G-J289-144G-J289-144G";
    const WRAPPED_RECOVERY_COPY: &str = "01030303030303030303030303030303030303030303030303\
        faeba636039561338c99c60f1e4c5e5f2fc03a8d69ecd52a3520ad26c961f19b\
        05d3f45912bea7fa40d758eb1583d30f";
    const CERTIFICATE: &str = "0a4f08011210010101010101010101010101010101011a10020202020202020202\
        02020202020202222013\
        98f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca2880d095ffbc3112408cc8f2\
        96c778a00bd714ea2ede5ef533598d2026eea078003c1ffc9ab22a902eba7d87645201bfada776609d1620\
        2c75c9e8204bb0b9b54b6f2bcbdc6334e904";

    fn unhex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn recovery_copy_format_is_stable() {
        let public = IdentityPublicKey::from_bytes(&unhex(IDENTITY_PUBLIC)).unwrap();
        let key =
            WrappingKey::from_recovery_key(&RecoveryKey::parse(RECOVERY_KEY).unwrap()).unwrap();

        let opened =
            AccountIdentityKey::unwrap(&unhex(WRAPPED_RECOVERY_COPY), &key, &public).unwrap();

        assert_eq!(opened.0.to_bytes(), IDENTITY_SEED);
    }

    #[test]
    fn certificate_format_is_stable() {
        let identity = AccountIdentityKey(SigningKey::from_bytes(&IDENTITY_SEED));
        let device = DeviceKey(SigningKey::from_bytes(&[8; 32]));

        let certificate =
            identity.certify_device(&[1; 16], &[2; 16], &device.public(), 1_700_000_000_000);

        assert_eq!(certificate, unhex(CERTIFICATE));
        assert!(
            identity
                .public()
                .verify_device_certificate(&unhex(CERTIFICATE))
                .is_ok()
        );
    }

    #[test]
    fn recovery_key_display_is_stable() {
        let key = RecoveryKey::parse(RECOVERY_KEY).unwrap();

        assert_eq!(key.display().as_str(), RECOVERY_KEY);
        assert_eq!(key.secret().expose(), &[9; 32]);
    }
}
