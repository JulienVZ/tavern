// SPDX-License-Identifier: AGPL-3.0-or-later

//! When this device updates its leaf in a group (ADR 0019, sections 3 and
//! 9). The sync engine (tasks 10b and 10c) asks it at each upkeep of a
//! group: at connection, every 24 hours, and right after a join.

use tavern_crypto::mls::Group;

/// How often a leaf is updated at least, even in a conversation without
/// messages.
pub const LEAF_UPDATE_PERIOD_MS: u64 = 7 * 24 * 3600 * 1000;

/// Whether this device must commit an update of its leaf in `group` now.
/// At once while its leaf is still the one its KeyPackage made (after a
/// join by Welcome, or the creation of the group): that leaf carries the
/// package's lifetime, and once it is over OpenMLS refuses every join of
/// the group (decided 2026-11-26). Otherwise once its last update is
/// [`LEAF_UPDATE_PERIOD_MS`] old.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "called by the sync engine of tasks 10b and 10c of M2"
    )
)]
pub(crate) fn leaf_update_due(group: &Group, last_update_ms: Option<u64>, now_ms: u64) -> bool {
    group.own_leaf_from_key_package()
        || last_update_ms.is_none_or(|last| now_ms.saturating_sub(last) >= LEAF_UPDATE_PERIOD_MS)
}
