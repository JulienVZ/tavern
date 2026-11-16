// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenMLS's in-memory storage is for tests only (ADR 0019, section 1). The
//! client keeps its MLS state in the encrypted local store and the server in
//! PostgreSQL; nothing else may hold it. `openmls_memory_storage` is in the
//! dependency graph anyway, through `openmls_rust_crypto`: this test makes
//! sure no production code of the workspace uses it.
//!
//! - No source file outside a test file (`tests.rs`, or a `tests/`
//!   directory) names it, its type or the provider that bundles it.
//! - No crate of the workspace depends on it outside `[dev-dependencies]`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: [&str; 3] = [
    "openmls_memory_storage",
    "MemoryStorage",
    "OpenMlsRustCrypto",
];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The source directories of the workspace's crates.
fn source_roots() -> Vec<PathBuf> {
    let root = workspace();
    let mut roots: Vec<PathBuf> = fs::read_dir(root.join("crates"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("src"))
        .filter(|path| path.is_dir())
        .collect();
    roots.push(root.join("apps/desktop/src-tauri/src"));
    roots
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "tests") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && path.file_name().is_some_and(|name| name != "tests.rs")
        {
            out.push(path);
        }
    }
}

#[test]
fn no_production_source_uses_the_in_memory_storage() {
    let mut files = Vec::new();
    for root in source_roots() {
        rust_files(&root, &mut files);
    }
    assert!(files.len() > 20, "the scan found the sources");

    let offenders: Vec<String> = files
        .iter()
        .flat_map(|file| {
            let text = fs::read_to_string(file).unwrap();
            FORBIDDEN
                .iter()
                .filter(|name| text.contains(*name))
                .map(|name| format!("{} names {name}", file.display()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(offenders.is_empty(), "{offenders:#?}");
}

#[test]
fn no_crate_depends_on_the_in_memory_storage_outside_dev_dependencies() {
    let root = workspace();
    let mut manifests: Vec<PathBuf> = fs::read_dir(root.join("crates"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("Cargo.toml"))
        .filter(|path| path.is_file())
        .collect();
    manifests.push(root.join("apps/desktop/src-tauri/Cargo.toml"));

    for manifest in manifests {
        let text = fs::read_to_string(&manifest).unwrap();
        let mut section = String::new();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                section = line.to_owned();
            } else if line.starts_with("openmls_memory_storage") {
                assert!(
                    section.contains("dev-dependencies"),
                    "{} depends on openmls_memory_storage in {section}",
                    manifest.display()
                );
            }
        }
    }
}
