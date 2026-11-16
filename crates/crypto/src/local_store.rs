// SPDX-License-Identifier: AGPL-3.0-or-later

//! The key of a device's local store, and how it is kept while the account
//! is signed out (ADR 0017).
//!
//! The store is encrypted with a random **store key**. While the account is
//! signed in, that key sits in the operating system's credential store. When
//! the account signs out it is removed, and only a **wrapped** copy stays.
//! Opening the wrapped copy takes two parts:
//!
//! - the **account part**, derived from the account root secret, which the
//!   client obtains by authenticating (the server never has it);
//! - the **server part**, random and kept by the server for this device,
//!   handed out only when the device opens a session and destroyed when the
//!   device is revoked.
//!
//! Neither part opens the store alone: the server cannot contribute to
//! reading it without the user's password, and someone with the password
//! cannot read the store of a device that was revoked.
//!
//! # Wrapped store key format (version 1, 73 bytes)
//!
//! ```text
//! 0x01 || nonce (24 bytes) || XChaCha20-Poly1305(store key, 32 bytes) || tag (16 bytes)
//! ```
//!
//! The wrapping key is `HKDF-SHA512(account part || server part, info =
//! label || 0x00 || device id)`. The associated data binds the copy to the
//! account and the device.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::identity::ID_LEN;
use crate::secret::Secret;
use crate::token::random_bytes;

/// Length of a store key, of each of its two parts, in bytes.
pub const PART_LEN: usize = 32;
/// Length of a wrapped store key, in bytes.
pub const WRAPPED_STORE_KEY_LEN: usize = 1 + NONCE_LEN + PART_LEN + TAG_LEN;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const VERSION: u8 = 1;
const LABEL_WRAP: &[u8] = b"tavern local store wrap v1";
const LABEL_AAD: &[u8] = b"tavern local store wrapped v1";

/// The two parts needed to open a wrapped store key, and what they are for.
#[derive(Debug)]
pub struct StoreKeyParts<'a> {
    /// From the account root secret (`AccountRootSecret::local_store_part`).
    pub account_part: &'a Secret<PART_LEN>,
    /// From the server, for this device.
    pub server_part: &'a Secret<PART_LEN>,
    /// The account.
    pub user_id: &'a [u8; ID_LEN],
    /// The device.
    pub device_id: &'a [u8; ID_LEN],
}

impl StoreKeyParts<'_> {
    fn wrapping_key(&self) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let mut input = Zeroizing::new([0u8; 2 * PART_LEN]);
        input[..PART_LEN].copy_from_slice(self.account_part.expose());
        input[PART_LEN..].copy_from_slice(self.server_part.expose());
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha512>::new(None, input.as_slice())
            .expand_multi_info(&[LABEL_WRAP, &[0], self.device_id], key.as_mut())
            .map_err(|_| CryptoError::Internal)?;
        Ok(key)
    }

    fn aad(&self) -> Vec<u8> {
        // A label without a zero byte, then fixed-length fields: unambiguous.
        [LABEL_AAD, &[0], self.user_id, self.device_id].concat()
    }

    /// Encrypts `store_key` so that it can be kept while signed out.
    pub fn wrap(&self, store_key: &Secret<PART_LEN>) -> Result<Vec<u8>, CryptoError> {
        self.wrap_with_nonce(store_key, &random_bytes())
    }

    fn wrap_with_nonce(
        &self,
        store_key: &Secret<PART_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = self.wrapping_key()?;
        let ciphertext = XChaCha20Poly1305::new(key.as_ref().into())
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: store_key.expose().as_slice(),
                    aad: &self.aad(),
                },
            )
            .map_err(|_| CryptoError::Internal)?;

        let mut out = Vec::with_capacity(WRAPPED_STORE_KEY_LEN);
        out.push(VERSION);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens a wrapped store key. Fails if either part is wrong, if the copy
    /// was made for another account or device, or if a byte was altered.
    pub fn unwrap(&self, wrapped: &[u8]) -> Result<Secret<PART_LEN>, CryptoError> {
        if wrapped.len() != WRAPPED_STORE_KEY_LEN {
            return Err(CryptoError::InvalidWrappedKey);
        }
        let (version, rest) = wrapped.split_at(1);
        if version != [VERSION] {
            return Err(CryptoError::UnsupportedVersion);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let key = self.wrapping_key()?;
        let opened = Zeroizing::new(
            XChaCha20Poly1305::new(key.as_ref().into())
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &self.aad(),
                    },
                )
                .map_err(|_| CryptoError::InvalidWrappedKey)?,
        );
        Secret::from_slice(&opened).ok_or(CryptoError::InvalidWrappedKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: [u8; ID_LEN] = [1; ID_LEN];
    const DEVICE: [u8; ID_LEN] = [2; ID_LEN];

    fn parts<'a>(account: &'a Secret<32>, server: &'a Secret<32>) -> StoreKeyParts<'a> {
        StoreKeyParts {
            account_part: account,
            server_part: server,
            user_id: &USER,
            device_id: &DEVICE,
        }
    }

    #[test]
    fn a_wrapped_store_key_opens_with_both_parts() {
        let (account, server, store_key) = (Secret::random(), Secret::random(), Secret::random());
        let wrapped = parts(&account, &server).wrap(&store_key).unwrap();

        assert_eq!(wrapped.len(), WRAPPED_STORE_KEY_LEN);
        assert!(
            parts(&account, &server)
                .unwrap(&wrapped)
                .unwrap()
                .ct_eq(&store_key)
        );
        // A fresh nonce every time.
        assert_ne!(wrapped, parts(&account, &server).wrap(&store_key).unwrap());
    }

    #[test]
    fn neither_part_is_enough_and_the_copy_is_bound_to_account_and_device() {
        let (account, server, store_key) = (Secret::random(), Secret::random(), Secret::random());
        let other = Secret::random();
        let wrapped = parts(&account, &server).wrap(&store_key).unwrap();
        let fails = |attempt: StoreKeyParts<'_>| {
            assert_eq!(
                attempt.unwrap(&wrapped).unwrap_err(),
                CryptoError::InvalidWrappedKey
            );
        };

        // The server's part with a wrong account part: what a host could try.
        fails(parts(&other, &server));
        // The account part with a wrong server part: a revoked device.
        fails(parts(&account, &other));
        // The two parts swapped.
        fails(parts(&server, &account));
        fails(StoreKeyParts {
            device_id: &USER,
            ..parts(&account, &server)
        });
        fails(StoreKeyParts {
            user_id: &DEVICE,
            ..parts(&account, &server)
        });
    }

    #[test]
    fn every_altered_byte_is_detected() {
        let (account, server, store_key) = (Secret::random(), Secret::random(), Secret::random());
        let wrapped = parts(&account, &server).wrap(&store_key).unwrap();

        for index in 0..wrapped.len() {
            let mut altered = wrapped.clone();
            altered[index] ^= 1;
            assert!(
                parts(&account, &server).unwrap(&altered).is_err(),
                "{index}"
            );
        }
        assert!(parts(&account, &server).unwrap(&wrapped[..72]).is_err());
        let mut newer = wrapped;
        newer[0] = 2;
        assert_eq!(
            parts(&account, &server).unwrap(&newer).unwrap_err(),
            CryptoError::UnsupportedVersion
        );
    }

    /// Known answer computed once and frozen: a change here would lock every
    /// signed-out device out of its local store.
    #[test]
    fn the_wrapped_format_is_stable() {
        const WRAPPED: &str = "01030303030303030303030303030303030303030303030303\
            6658b27ff2c383c331fd71bf0cedd04e9fed8442b98a4dcde57425d3c8ad4cf8\
            6b0d466e83d8857a42f7f6f88a828734";
        let (account, server) = (Secret::new([4; 32]), Secret::new([5; 32]));
        let store_key = Secret::new([6; 32]);

        let wrapped = parts(&account, &server)
            .wrap_with_nonce(&store_key, &[3; NONCE_LEN])
            .unwrap();
        let hex: String = wrapped.iter().map(|byte| format!("{byte:02x}")).collect();

        assert_eq!(hex, WRAPPED);
    }
}
