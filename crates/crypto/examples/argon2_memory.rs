// SPDX-License-Identifier: AGPL-3.0-or-later

//! Measures how long one client-side OPAQUE registration takes and checks
//! that the Argon2id working memory (128 MiB) is returned afterwards.
//!
//! ```sh
//! cargo run --release --package tavern-crypto --example argon2_memory
//! ```
//!
//! Results are recorded in `docs/adr/0003-opaque-authentication.md`.

#![allow(clippy::print_stdout, reason = "command-line measurement tool")]

use std::process::Command;
use std::time::Instant;

use tavern_crypto::opaque::Password;
use tavern_crypto::opaque::client::Registration;
use tavern_crypto::opaque::server::ServerSetup;
use tavern_protocol::handle::Handle;

/// Resident memory of this process in MiB, read from `ps` (Unix only).
fn resident_mib() -> Option<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kib: u64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
    Some(kib / 1024)
}

/// Physical footprint in MiB as reported by macOS `top`: the figure Activity
/// Monitor shows. Unlike resident size, it excludes pages the allocator has
/// already handed back to the system as reusable.
fn footprint() -> Option<String> {
    let output = Command::new("top")
        .args([
            "-l",
            "1",
            "-pid",
            &std::process::id().to_string(),
            "-stats",
            "mem",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    text.lines()
        .last()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
}

fn show(label: &str) {
    let resident = resident_mib().map_or_else(|| "?".to_owned(), |mib| format!("{mib} MiB"));
    let footprint = footprint().unwrap_or_else(|| "n/a".to_owned());
    println!("{label:<26} resident {resident:>8}   footprint {footprint:>6}");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let setup = ServerSetup::generate();
    let handle = Handle::parse_canonical("measure")?;
    let password = Password::new("correct horse battery staple");

    show("before");
    for round in 1..=3 {
        let (state, request) = Registration::start(&password)?;
        let response = setup.registration_start(&request, &handle)?;
        let started = Instant::now();
        let output = state.finish(&password, &response, &handle)?;
        let elapsed = started.elapsed();
        drop(output);
        show(&format!("after run {round} ({} ms)", elapsed.as_millis()));
    }
    // Allocators may hand large blocks back to the system with a short delay.
    for seconds in [2u64, 10] {
        std::thread::sleep(std::time::Duration::from_secs(seconds));
        show(&format!("{seconds} s later"));
    }
    Ok(())
}
