// SPDX-License-Identifier: AGPL-3.0-or-later

//! Padding of message content before MLS encryption (ADR 0019, section 8),
//! so that the server sees one of a few sizes.
//!
//! ```text
//! length of the content (4 bytes, big-endian) || content || zero bytes
//! ```
//!
//! The whole is exactly one of [`BUCKETS`]: multiples of 256 bytes up to
//! 1 KiB, then powers of two up to 64 KiB. Decoding is strict: a size that
//! is not a bucket, a length beyond the data, or a padding byte that is not
//! zero are all refused.

use zeroize::Zeroizing;

/// The sizes a padded content can have, in bytes.
pub const BUCKETS: [usize; 10] = [
    256,
    512,
    768,
    1024,
    2 * 1024,
    4 * 1024,
    8 * 1024,
    16 * 1024,
    32 * 1024,
    64 * 1024,
];
const HEADER: usize = 4;
/// The largest content that can be padded, in bytes.
pub const MAX_CONTENT: usize = 64 * 1024 - HEADER;

/// Why padded content was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PaddingError {
    /// The content is larger than [`MAX_CONTENT`].
    #[error("the content is too large")]
    TooLarge,
    /// The padded size is not one of [`BUCKETS`].
    #[error("the size is not a padding bucket")]
    NotABucket,
    /// The announced length goes beyond the data.
    #[error("the announced length goes beyond the data")]
    LengthBeyondData,
    /// A padding byte is not zero.
    #[error("a padding byte is not zero")]
    NonZeroPadding,
}

/// Pads `content` to the smallest bucket that holds it. The padded copy is
/// plaintext: it is erased when dropped.
pub fn pad(content: &[u8]) -> Result<Zeroizing<Vec<u8>>, PaddingError> {
    let needed = content
        .len()
        .checked_add(HEADER)
        .ok_or(PaddingError::TooLarge)?;
    let size = *BUCKETS
        .iter()
        .find(|bucket| **bucket >= needed)
        .ok_or(PaddingError::TooLarge)?;
    let length = u32::try_from(content.len()).map_err(|_| PaddingError::TooLarge)?;
    // Allocated at its final size, so that it never moves (and leaves a
    // copy behind) while it is filled.
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(content);
    out.resize(size, 0);
    Ok(out)
}

/// Removes the padding, refusing anything [`pad`] would not have produced
/// in one of the buckets.
pub fn unpad(padded: &[u8]) -> Result<&[u8], PaddingError> {
    if !BUCKETS.contains(&padded.len()) {
        return Err(PaddingError::NotABucket);
    }
    let (length, rest) = padded.split_at(HEADER);
    let length = usize::try_from(u32::from_be_bytes(
        length.try_into().map_err(|_| PaddingError::NotABucket)?,
    ))
    .map_err(|_| PaddingError::LengthBeyondData)?;
    if length > rest.len() {
        return Err(PaddingError::LengthBeyondData);
    }
    let (content, padding) = rest.split_at(length);
    if padding.iter().any(|byte| *byte != 0) {
        return Err(PaddingError::NonZeroPadding);
    }
    Ok(content)
}
