// SPDX-License-Identifier: AGPL-3.0-or-later

//! The Argon2id working memory (128 MiB) is back with the operating system
//! as soon as a client-side OPAQUE operation returns.
//!
//! This is the regression test for the retention measured on macOS 26
//! (`docs/adr/0015-argon2-working-memory.md`). It lives in its own test
//! binary, with a single test, so that nothing else allocates in the process
//! while it measures. CI runs it on Linux, macOS and Windows.

#![allow(clippy::print_stdout, reason = "the measurements belong in the CI log")]

#[path = "support/footprint.rs"]
mod footprint;

use footprint::{FOOTPRINT_KIND, footprint_bytes, mib};
use tavern_crypto::opaque::client::Registration;
use tavern_crypto::opaque::server::ServerSetup;
use tavern_crypto::opaque::{ARGON2_MEMORY_KIB, Password};
use tavern_protocol::handle::Handle;

/// Growth tolerated between "before" and "right after": a quarter of the
/// working memory. Retaining the block would show as the whole of it.
const TOLERATED_GROWTH: u64 = ARGON2_MEMORY_KIB as u64 * 1024 / 4;

fn measure() -> u64 {
    let Some(bytes) = footprint_bytes() else {
        panic!("the memory footprint of this process could not be measured");
    };
    bytes
}

#[test]
fn working_memory_is_returned_as_soon_as_the_computation_ends() {
    let setup = ServerSetup::generate();
    let handle = Handle::parse_canonical("measure").unwrap();
    let password = Password::new("correct horse battery staple");

    let before = measure();
    println!("{FOOTPRINT_KIND} before: {}", mib(before));

    for round in 1..=3 {
        let (state, request) = Registration::start(&password).unwrap();
        let response = setup.registration_start(&request, &handle).unwrap();
        let output = state.finish(&password, &response, &handle).unwrap();
        drop(output);

        // No delay: the memory must be gone by now, not eventually.
        let after = measure();
        println!("{FOOTPRINT_KIND} after run {round}: {}", mib(after));
        assert!(
            after < before + TOLERATED_GROWTH,
            "the Argon2id working memory was not returned: {} before, {} after run {round}",
            mib(before),
            mib(after),
        );
    }
}
