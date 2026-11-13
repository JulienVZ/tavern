// SPDX-License-Identifier: AGPL-3.0-or-later

//! :identity::v1::DeviceCertificate:Device certificates, decoded by the server and by every client that verifies one.
//!
//! Decoding arbitrary bytes must never panic, and whatever decodes must
//! encode and decode again to the same value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use tavern_protocol as Target;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = Target::decode(data) {
        let encoded = decoded.encode_to_vec();
        let again = Target::decode(encoded.as_slice()).expect("re-decoding an encoded message");
        assert_eq!(decoded, again);
    }
});
