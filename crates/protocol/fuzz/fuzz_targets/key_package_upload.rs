// SPDX-License-Identifier: AGPL-3.0-or-later

//! KeyPackage uploads, decoded and checked by the server for every device
//! (ADR 0019, sections 3 and 18).
//!
//! Checking arbitrary bytes must never panic, in either slot. Random bytes
//! never make a valid package of the uploader: the target exercises the
//! decoder and the refusals that follow it.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tavern_crypto::identity::{AccountRootSecret, DeviceKey};
use tavern_crypto::mls::key_package::{self, Uploader};

fn uploader() -> &'static Uploader {
    static UPLOADER: OnceLock<Uploader> = OnceLock::new();
    UPLOADER.get_or_init(|| {
        let identity = AccountRootSecret::generate()
            .identity_key()
            .expect("an identity key");
        let key = DeviceKey::generate();
        let (user_id, device_id) = ([1; 16], [2; 16]);
        Uploader {
            user_id,
            device_id,
            identity_key: identity.public(),
            signature_key: key.public().to_bytes().to_vec(),
            certificate: identity.certify_device(&user_id, &device_id, &key.public(), 0),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    for last_resort in [false, true] {
        let _ = key_package::validate_upload(data, uploader(), last_resort);
    }
});
