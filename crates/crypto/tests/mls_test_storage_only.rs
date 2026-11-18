// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenMLS's in-memory storage is for tests only (ADR 0019, section 1). The
//! client keeps its MLS state in the encrypted local store and the server in
//! PostgreSQL; nothing else may hold it.
//!
//! `openmls_memory_storage` is in the dependency graph anyway, through
//! `openmls_rust_crypto`. This test reads the graph Cargo resolves (`cargo
//! metadata`, so that a renamed dependency is seen as what it is) and fails
//! if any crate of the workspace depends on it outside
//! `[dev-dependencies]`. CI also checks the production binaries: no symbol of
//! `openmls_memory_storage` may be linked into the server or the client,
//! which also covers its re-export by `openmls_rust_crypto`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

const TEST_ONLY: &str = "openmls_memory_storage";

#[test]
fn no_workspace_crate_depends_on_the_in_memory_storage_outside_dev_dependencies() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    // Not `--offline`: the graph covers every platform, and a build on this
    // one never fetches the crates of the others (sqlx 0.9.1 brought one for
    // Apple systems only, which a Linux runner had never downloaded).
    // `--locked` keeps it the graph of Cargo.lock.
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(&manifest)
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();

    let members: Vec<&str> = metadata["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    let mut checked = 0;
    let mut offenders = Vec::new();
    for package in metadata["packages"].as_array().unwrap() {
        if !members.contains(&package["id"].as_str().unwrap()) {
            continue;
        }
        checked += 1;
        for dependency in package["dependencies"].as_array().unwrap() {
            // `name` is the package's name, whatever it is renamed to.
            if dependency["name"] == TEST_ONLY && dependency["kind"] != "dev" {
                offenders.push(format!(
                    "{} ({} dependency, as {})",
                    package["name"],
                    dependency["kind"].as_str().unwrap_or("normal"),
                    dependency["rename"].as_str().unwrap_or(TEST_ONLY)
                ));
            }
        }
    }
    assert!(checked >= 8, "found the workspace's crates ({checked})");
    assert!(offenders.is_empty(), "{offenders:#?}");
}
