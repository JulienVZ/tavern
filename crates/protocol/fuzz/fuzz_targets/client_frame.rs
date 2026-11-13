// SPDX-License-Identifier: AGPL-3.0-or-later

//! :gateway::v1::ClientFrame:Frames sent by clients to the gateway: the server decodes these from the network.
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
