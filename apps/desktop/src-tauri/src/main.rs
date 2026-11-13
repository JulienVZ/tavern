// SPDX-License-Identifier: AGPL-3.0-or-later

// Do not open a console window next to the application on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    match tavern_desktop_lib::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[expect(clippy::print_stderr, reason = "last-resort error report before exit")]
            {
                eprintln!("error: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
