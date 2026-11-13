// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compiles the `.proto` files with `protox` (pure Rust), so that building the
//! workspace does not require `protoc`. See `docs/adr/0005-protobuf-protocol.md`.

use std::error::Error;

const PROTO_ROOT: &str = "proto";
const PROTO_FILES: &[&str] = &["tavern/gateway/v1/gateway.proto"];

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={PROTO_ROOT}");

    let descriptors = protox::compile(PROTO_FILES, [PROTO_ROOT])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
