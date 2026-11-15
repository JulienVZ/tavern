// SPDX-License-Identifier: AGPL-3.0-or-later

//! Working memory for Argon2id, erased and handed back to the operating
//! system as soon as it is dropped.
//!
//! Argon2id needs a large scratch area (128 MiB with Tavern's parameters) for
//! a fraction of a second. Taken from the general-purpose allocator, that
//! area may stay charged to the process long after the computation: macOS 26
//! still holds it thirty seconds later (measurements in
//! `docs/adr/0015-argon2-working-memory.md`). [`WorkingMemory`] takes it from
//! a private anonymous mapping instead, and unmaps it on drop.
//!
//! This crate exists so that the `unsafe` code this requires lives outside
//! `tavern-crypto`, which forbids it, and can be reviewed on its own. It
//! contains nothing else: no cryptography, no parameters, no policy.
//!
//! # Guarantees
//!
//! - The memory is zero-filled when handed out.
//! - It is erased (`zeroize`) before being released, on every path that drops
//!   the value: normal return, early return on error, and unwinding from a
//!   panic. With `panic = "abort"` (release builds of the client) a panic
//!   ends the process without running destructors; the system then reclaims
//!   the pages and never hands them to another process without clearing them.
//! - On Unix it is returned to the system by `munmap` at drop, not cached.
//! - On other systems it comes from the global allocator and is erased before
//!   being freed. Windows gives blocks of this size back at once (ADR 0015).
//!
//! The memory is not locked (`mlock`): it can be written to swap while the
//! computation runs, like any other memory of the process.

use argon2::Block;
use zeroize::Zeroize;

/// Why the working memory could not be obtained.
#[derive(Debug, thiserror::Error)]
pub enum AllocationError {
    /// Zero blocks were requested.
    #[error("no working memory was requested")]
    Empty,
    /// The requested size does not fit in the address space.
    #[error("the requested working memory is too large")]
    TooLarge,
    /// The operating system refused the request.
    #[error("the operating system could not provide the working memory")]
    OutOfMemory,
}

/// A zero-filled run of Argon2 blocks, erased and released on drop.
pub struct WorkingMemory {
    region: imp::Region,
}

impl WorkingMemory {
    /// Obtains `blocks` zero-filled blocks of 1 KiB each.
    pub fn new(blocks: usize) -> Result<Self, AllocationError> {
        if blocks == 0 {
            return Err(AllocationError::Empty);
        }
        // Rust objects may not exceed `isize::MAX` bytes.
        let bytes = blocks
            .checked_mul(size_of::<Block>())
            .filter(|bytes| isize::try_from(*bytes).is_ok())
            .ok_or(AllocationError::TooLarge)?;
        Ok(Self {
            region: imp::Region::new(blocks, bytes)?,
        })
    }

    /// The blocks, for `Argon2::hash_password_into_with_memory`.
    pub fn blocks(&mut self) -> &mut [Block] {
        self.region.blocks()
    }
}

impl AsMut<[Block]> for WorkingMemory {
    fn as_mut(&mut self) -> &mut [Block] {
        self.blocks()
    }
}

impl Drop for WorkingMemory {
    fn drop(&mut self) {
        // Erased first; the region's own destructor then releases the memory.
        self.region.blocks().iter_mut().zeroize();
        #[cfg(test)]
        tests::record_drop(self.region.blocks());
    }
}

// The layout the Unix implementation relies on, checked at compile time: a
// block is exactly 1024 bytes without padding, and its alignment is no
// stricter than the smallest page size of any supported system (4 KiB).
const _: () = assert!(size_of::<Block>() == 1024);
const _: () = assert!(align_of::<Block>() <= 4096);

#[cfg(unix)]
mod imp {
    use std::ptr::{self, NonNull};

    use argon2::Block;

    use super::AllocationError;

    /// A private anonymous mapping holding `blocks` Argon2 blocks.
    ///
    /// Invariant: `start` is the address returned by a successful `mmap` of
    /// exactly `bytes` bytes (`bytes == blocks * size_of::<Block>()`),
    /// readable and writable, aligned for `Block`, owned by this value alone
    /// and still mapped.
    pub(super) struct Region {
        start: NonNull<Block>,
        blocks: usize,
        bytes: usize,
    }

    impl Region {
        pub(super) fn new(blocks: usize, bytes: usize) -> Result<Self, AllocationError> {
            // SAFETY: `mmap` with a null address hint and without `MAP_FIXED`
            // never touches existing mappings: the kernel picks a free range.
            // The mapping is anonymous (`MAP_ANON`, descriptor -1, offset 0),
            // so no file is involved, and private. `bytes` is non-zero
            // (checked by the caller). Failure is reported as `MAP_FAILED`
            // and handled below.
            let address = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if address == libc::MAP_FAILED {
                return Err(AllocationError::OutOfMemory);
            }
            let start = address.cast::<Block>();
            match NonNull::new(start) {
                // `mmap` returns page-aligned addresses and a page is at
                // least 4 KiB (see the assertion above), so this always
                // holds; it is checked rather than assumed because `blocks()`
                // depends on it.
                Some(start) if start.is_aligned() => Ok(Self {
                    start,
                    blocks,
                    bytes,
                }),
                _ => {
                    // SAFETY: `address` and `bytes` describe the mapping
                    // created just above, which nothing else refers to.
                    unsafe { libc::munmap(address, bytes) };
                    Err(AllocationError::OutOfMemory)
                }
            }
        }

        pub(super) fn blocks(&mut self) -> &mut [Block] {
            // SAFETY: by the invariant, `start` points to `bytes` mapped,
            // readable and writable bytes, aligned for `Block`, and
            // `bytes == blocks * size_of::<Block>()` does not exceed
            // `isize::MAX` (checked in `WorkingMemory::new`). Anonymous
            // mappings are zero-filled, and `Block` is an array of `u64`
            // without padding (size asserted above), so every bit pattern,
            // zeros included, is a valid value: the memory is initialised.
            // The returned borrow is tied to `&mut self`, so it cannot
            // outlive the mapping nor alias another reference to it.
            unsafe { std::slice::from_raw_parts_mut(self.start.as_ptr(), self.blocks) }
        }
    }

    impl Drop for Region {
        fn drop(&mut self) {
            // SAFETY: by the invariant, `start` and `bytes` are exactly the
            // address and length of a mapping this value owns. `&mut self`
            // in a destructor guarantees no reference into it remains, and
            // the value is not used afterwards. The result is ignored:
            // `munmap` cannot fail for a range that is a whole, live mapping,
            // and there would be nothing to do about it here.
            unsafe { libc::munmap(self.start.as_ptr().cast(), self.bytes) };
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use argon2::Block;

    use super::AllocationError;

    /// Blocks from the global allocator. No `unsafe` code on this path.
    pub(super) struct Region {
        blocks: Vec<Block>,
    }

    impl Region {
        pub(super) fn new(blocks: usize, _bytes: usize) -> Result<Self, AllocationError> {
            let mut memory = Vec::new();
            memory
                .try_reserve_exact(blocks)
                .map_err(|_| AllocationError::OutOfMemory)?;
            memory.resize(blocks, Block::default());
            Ok(Self { blocks: memory })
        }

        pub(super) fn blocks(&mut self) -> &mut [Block] {
            &mut self.blocks
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use argon2::{Algorithm, Argon2, Params, Version};

    use super::*;

    thread_local! {
        /// Number of `WorkingMemory` values dropped on this thread whose
        /// blocks were all zero when the destructor had finished erasing.
        static ERASED_DROPS: Cell<usize> = const { Cell::new(0) };
    }

    /// Called by the destructor, after erasing and before releasing.
    pub(super) fn record_drop(blocks: &[Block]) {
        let erased = blocks
            .iter()
            .all(|block| block.as_ref().iter().all(|word| *word == 0));
        assert!(erased, "working memory was not erased before release");
        ERASED_DROPS.with(|count| count.set(count.get() + 1));
    }

    fn erased_drops() -> usize {
        ERASED_DROPS.with(Cell::get)
    }

    fn fill(memory: &mut WorkingMemory) {
        for (index, block) in memory.blocks().iter_mut().enumerate() {
            for word in block.as_mut() {
                *word = u64::MAX - index as u64;
            }
        }
    }

    #[test]
    fn memory_is_handed_out_zeroed_with_the_requested_size() {
        for blocks in [1, 3, 8, 64] {
            let mut memory = WorkingMemory::new(blocks).unwrap();
            assert_eq!(memory.blocks().len(), blocks);
            assert!(
                memory
                    .blocks()
                    .iter()
                    .all(|block| block.as_ref().iter().all(|word| *word == 0))
            );
        }
    }

    #[test]
    fn every_block_can_be_written_and_read_back() {
        let mut memory = WorkingMemory::new(16).unwrap();
        fill(&mut memory);
        for (index, block) in memory.blocks().iter().enumerate() {
            assert!(
                block
                    .as_ref()
                    .iter()
                    .all(|word| *word == u64::MAX - index as u64)
            );
        }
        assert_eq!(memory.as_mut().len(), 16);
    }

    #[test]
    fn memory_is_erased_before_release() {
        let before = erased_drops();
        let mut memory = WorkingMemory::new(8).unwrap();
        fill(&mut memory);
        drop(memory);
        assert_eq!(erased_drops(), before + 1);
    }

    #[test]
    fn memory_is_erased_when_an_error_returns_early() {
        fn fails(memory: &mut WorkingMemory) -> Result<(), ()> {
            fill(memory);
            Err(())
        }
        fn run() -> Result<(), ()> {
            let mut memory = WorkingMemory::new(8).map_err(|_| ())?;
            fails(&mut memory)?;
            Ok(())
        }
        let before = erased_drops();
        assert!(run().is_err());
        assert_eq!(erased_drops(), before + 1);
    }

    #[test]
    fn memory_is_erased_when_a_panic_unwinds() {
        let before = erased_drops();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let mut memory = WorkingMemory::new(8).unwrap();
            fill(&mut memory);
            panic!("deliberate panic while the memory holds data");
        }));
        assert!(outcome.is_err());
        assert_eq!(erased_drops(), before + 1);
    }

    #[test]
    fn zero_blocks_are_refused() {
        assert!(matches!(WorkingMemory::new(0), Err(AllocationError::Empty)));
    }

    #[test]
    fn sizes_beyond_the_address_space_are_refused() {
        for blocks in [
            usize::MAX,
            usize::MAX / 1024 + 1,
            isize::MAX as usize / 1024 + 1,
        ] {
            assert!(matches!(
                WorkingMemory::new(blocks),
                Err(AllocationError::TooLarge)
            ));
        }
    }

    #[test]
    fn a_request_the_system_cannot_satisfy_is_an_error() {
        // Fits in `isize` but far exceeds any address space in use.
        let blocks = isize::MAX as usize / 1024;
        assert!(matches!(
            WorkingMemory::new(blocks),
            Err(AllocationError::OutOfMemory)
        ));
    }

    #[test]
    fn many_regions_can_be_taken_and_released() {
        let before = erased_drops();
        for _ in 0..32 {
            let mut memory = WorkingMemory::new(4).unwrap();
            fill(&mut memory);
        }
        let mut first = WorkingMemory::new(2).unwrap();
        let mut second = WorkingMemory::new(2).unwrap();
        fill(&mut first);
        assert!(
            second
                .blocks()
                .iter()
                .all(|block| block.as_ref().iter().all(|word| *word == 0))
        );
        drop(first);
        drop(second);
        assert_eq!(erased_drops(), before + 34);
    }

    /// Argon2id gives the same result in this memory as in memory it
    /// allocates itself, and the memory is erased afterwards.
    #[test]
    fn argon2_computes_the_same_hash_in_this_memory() {
        let params = Params::new(8, 1, 1, Some(32)).unwrap();
        let blocks = params.block_count();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut expected = [0u8; 32];
        argon2
            .hash_password_into(b"password", b"0123456789abcdef", &mut expected)
            .unwrap();

        let before = erased_drops();
        let mut actual = [0u8; 32];
        let mut memory = WorkingMemory::new(blocks).unwrap();
        argon2
            .hash_password_into_with_memory(
                b"password",
                b"0123456789abcdef",
                &mut actual,
                &mut memory,
            )
            .unwrap();
        assert!(
            memory
                .blocks()
                .iter()
                .any(|block| block.as_ref().iter().any(|word| *word != 0)),
            "Argon2id wrote to the working memory"
        );
        drop(memory);

        assert_eq!(actual, expected);
        assert_eq!(erased_drops(), before + 1);
    }
}
