// SPDX-License-Identifier: AGPL-3.0-or-later

//! The generation of a conversation's MLS group (ADR 0019, section 17): the
//! 32 bits after the conversation id in the group id. Client and server
//! compute it the same way.
//!
//! Its high 16 bits are an instance generation, raised by each restore of a
//! backup (section 15); its low 16 bits count the recreations within it. A
//! group recreated after a restore takes the first generation of the new
//! instance generation, which no group of the conversation can have had
//! before the restore, whatever was lost with the database. Outside a
//! restore, a recreation takes the next generation, in the same block.

/// Recreations of a conversation's group within one instance generation.
pub const PER_INSTANCE_GENERATION: u32 = 1 << 16;

/// The generation of the group recreated after the restore that brought the
/// instance to `instance_generation`; `None` past the last instance
/// generation that fits (65535 restores).
pub fn after_restore(instance_generation: u64) -> Option<u32> {
    let block = u32::try_from(instance_generation).ok()?;
    if block == 0 {
        return None;
    }
    block.checked_mul(PER_INSTANCE_GENERATION)
}

/// The generation that recreates a group of generation `current` at a
/// user's request; `None` once the 65536 generations of its block are used.
pub fn next(current: u32) -> Option<u32> {
    let next = current.checked_add(1)?;
    (next % PER_INSTANCE_GENERATION != 0).then_some(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restore_starts_a_block_no_earlier_generation_reaches() {
        assert_eq!(after_restore(0), None);
        assert_eq!(after_restore(1), Some(65_536));
        assert_eq!(after_restore(2), Some(131_072));
        assert_eq!(after_restore(65_535), Some(0xFFFF_0000));
        assert_eq!(after_restore(65_536), None);
        assert_eq!(after_restore(u64::MAX), None);
        // Every recreation at a user's request stays in its block.
        assert_eq!(next(0), Some(1));
        assert_eq!(next(65_534), Some(65_535));
        assert_eq!(next(65_535), None);
        assert_eq!(next(65_536), Some(65_537));
        assert_eq!(next(u32::MAX), None);
    }
}
