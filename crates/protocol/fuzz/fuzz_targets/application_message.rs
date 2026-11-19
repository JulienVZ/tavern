// SPDX-License-Identifier: AGPL-3.0-or-later

//! Application messages, whose header the server reads before it sequences
//! them (`SendMessage`, ADR 0019, sections 7 and 18).
//!
//! Reading the header of arbitrary bytes must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tavern_crypto::mls::application_header;

fuzz_target!(|data: &[u8]| {
    let _ = application_header(data);
});
