// SPDX-License-Identifier: AGPL-3.0-or-later

fn main() {
    // `sqlx::migrate!` embeds the migrations at compile time. Without this,
    // cargo does not rebuild the crate when a migration file is added.
    println!("cargo:rerun-if-changed=migrations");
}
