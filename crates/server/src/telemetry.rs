// SPDX-License-Identifier: AGPL-3.0-or-later

//! Logging set-up.
//!
//! Logs stay on the host: nothing is sent to a third party. Secrets, tokens,
//! keys, ciphertext and plaintext must never be logged.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::ParseError;

use crate::config::LogFormat;

/// Installs the global `tracing` subscriber.
///
/// `level` is a filter directive such as `info` or `tavern_server=debug,info`.
pub fn init(level: &str, format: LogFormat) -> Result<(), ParseError> {
    let filter = EnvFilter::builder().parse(level)?;
    // Colours only when a person is watching: container logs stay plain text.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal());

    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
    Ok(())
}
