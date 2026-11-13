// SPDX-License-Identifier: AGPL-3.0-or-later

/// A cryptographic operation failed.
///
/// Variants are deliberately coarse: they never say why a secret was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// A message from the other side could not be decoded.
    #[error("malformed cryptographic message")]
    InvalidMessage,
    /// OPAQUE login failed: wrong password, or a tampered exchange.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// A signature does not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// A wrapped key could not be opened: wrong key, wrong account or tampering.
    #[error("the wrapped key cannot be opened")]
    InvalidWrappedKey,
    /// A structure carries a version this build does not understand.
    #[error("unsupported format version")]
    UnsupportedVersion,
    /// A recovery key or code is not correctly formed.
    #[error("malformed key or code")]
    InvalidEncoding,
    /// A primitive reported an internal failure.
    #[error("internal cryptographic failure")]
    Internal,
}
