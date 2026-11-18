// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which devices are active (ADR 0019, section 3): not revoked, of an
//! account that is not disabled, and seen within `TAVERN_DEVICE_INACTIVE_DAYS`.
//!
//! One definition for every place the ADR says "active devices": the devices
//! a KeyPackage claim serves, and the devices the server accepts as leaves of
//! a group ([`ServerRoster`](crate::mls::ServerRoster)). An inactive device
//! would otherwise be added to new conversations only to be removed from
//! them.

/// Default of `TAVERN_DEVICE_INACTIVE_DAYS`: the retention period.
pub const DEFAULT_INACTIVE_DAYS: u32 = 30;
/// Largest `TAVERN_DEVICE_INACTIVE_DAYS`: never longer than the retention
/// period, which is 30 days at most (ADR 0019, section 15).
pub const MAX_INACTIVE_DAYS: u32 = 30;

/// The SQL condition, on `devices d JOIN users u ON u.id = d.user_id`, that
/// an active device meets, with the window in days bound as the parameter
/// named (`"$2"`, ...), whose value is [`window`]. A string literal, for
/// `concat!`: queries stay static.
///
/// The server records a device's activity per day (`devices.last_seen_at`),
/// so the window counts whole days: a device last seen 30 days ago is still
/// active with the default window, one seen 31 days ago is not. A device not
/// seen since its enrolment counts from its enrolment.
macro_rules! active_device {
    ($window:literal) => {
        concat!(
            "d.revoked_at IS NULL AND u.disabled_at IS NULL \
             AND COALESCE(d.last_seen_at, d.created_at) \
             >= date_trunc('day', now()) - make_interval(days => ",
            $window,
            ")"
        )
    };
}
pub(crate) use active_device;

/// The value to bind for the window of `active_device!`.
pub fn window(inactive_days: u32) -> i32 {
    i32::try_from(inactive_days.min(MAX_INACTIVE_DAYS)).unwrap_or(i32::MAX)
}
