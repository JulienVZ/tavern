// SPDX-License-Identifier: AGPL-3.0-or-later

//! Memory charged to the current process, as the operating system reports it.
//!
//! Shared by the `argon2_memory_release` test and the `argon2_memory`
//! example. Each system has its own honest figure for "memory this process
//! really holds":
//!
//! - macOS: the **physical footprint** of `vmmap --summary`, what Activity
//!   Monitor shows as "Memory". Resident size is misleading there: it keeps
//!   counting pages the allocator has already marked reusable.
//! - Linux: resident set size (`VmRSS` in `/proc/self/status`).
//! - Windows: private bytes (`PrivateMemorySize64`), the committed memory
//!   that belongs to the process alone.

use std::process::Command;

/// Bytes charged to this process, or `None` if the system's tool could not
/// be run or understood.
pub fn footprint_bytes() -> Option<u64> {
    imp::footprint_bytes()
}

/// Name of the figure measured on this system.
pub const FOOTPRINT_KIND: &str = imp::KIND;

/// Formats a byte count in MiB with one decimal.
pub fn mib(bytes: u64) -> String {
    format!(
        "{}.{} MiB",
        bytes / 1_048_576,
        bytes % 1_048_576 * 10 / 1_048_576
    )
}

#[allow(dead_code, reason = "not used on every operating system")]
fn output_of(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    String::from_utf8(output.stdout).ok()
}

#[cfg(target_os = "macos")]
mod imp {
    pub const KIND: &str = "physical footprint";

    pub fn footprint_bytes() -> Option<u64> {
        let summary = super::output_of("vmmap", &["--summary", &std::process::id().to_string()])?;
        let value = summary
            .lines()
            .find(|line| line.starts_with("Physical footprint:"))?
            .split(':')
            .nth(1)?
            .trim();
        // "1.4M", "129.1M", "512K", "1.2G"
        let (number, unit) = value.split_at(value.len().checked_sub(1)?);
        let scale = match unit {
            "B" => 1.0,
            "K" => 1024.0,
            "M" => 1024.0 * 1024.0,
            "G" => 1024.0 * 1024.0 * 1024.0,
            _ => return None,
        };
        let number: f64 = number.trim().parse().ok()?;
        Some((number * scale) as u64)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    pub const KIND: &str = "resident set size";

    pub fn footprint_bytes() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kib: u64 = status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kib * 1024)
    }
}

#[cfg(windows)]
mod imp {
    pub const KIND: &str = "private bytes";

    pub fn footprint_bytes() -> Option<u64> {
        let command = format!(
            "(Get-Process -Id {}).PrivateMemorySize64",
            std::process::id()
        );
        super::output_of(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &command],
        )?
        .trim()
        .parse()
        .ok()
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod imp {
    pub const KIND: &str = "unavailable";

    pub fn footprint_bytes() -> Option<u64> {
        None
    }
}
