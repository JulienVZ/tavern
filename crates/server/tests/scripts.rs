// SPDX-License-Identifier: AGPL-3.0-or-later

//! The functions of `deploy/scripts/lib/archive.sh`, run by `sh`: the date
//! of a backup that `restore.sh` records (ADR 0019, section 15). Unix only,
//! as the scripts.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use std::path::Path;
use std::process::Command;

fn library() -> String {
    format!(
        "{}/../../deploy/scripts/lib/archive.sh",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn run(script: &str, args: &[&str], stdin: &str) -> String {
    use std::io::Write;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!(". '{}' && {script}", library()))
        .arg("sh")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn backup_date(dir: &Path) -> String {
    run("backup_date \"$1\"", &[dir.to_str().unwrap()], "")
}

#[test]
fn the_date_of_a_backup_comes_from_its_file_then_its_name_and_is_checked() {
    let root = tempfile::tempdir().unwrap();
    let named = root.path().join("tavern-20261101T100000Z");
    std::fs::create_dir(&named).unwrap();
    // From the name, without the file.
    assert_eq!(backup_date(&named), "2026-11-01T10:00:00Z\n");
    // The file wins.
    std::fs::write(named.join("taken_at"), "2026-11-02T08:30:00Z\n").unwrap();
    assert_eq!(backup_date(&named), "2026-11-02T08:30:00Z\n");
    // A file that is not a date gives none, whatever the name says.
    std::fs::write(
        named.join("taken_at"),
        "2026-11-02'; DROP TABLE users; --\n",
    )
    .unwrap();
    assert_eq!(backup_date(&named), "");
    // Neither file nor name.
    let other = root.path().join("my-backup");
    std::fs::create_dir(&other).unwrap();
    assert_eq!(backup_date(&other), "");
    let wrong = root.path().join("tavern-2026110T100000Z");
    std::fs::create_dir(&wrong).unwrap();
    assert_eq!(backup_date(&wrong), "");
}

#[test]
fn the_newest_migration_is_read_from_the_dump() {
    let listing = "\
--
-- Data for Name: _sqlx_migrations; Type: TABLE DATA
--

COPY public._sqlx_migrations (version, description, installed_on, success, checksum, execution_time) FROM stdin;
1\tinit\t2026-11-01\tt\t\\\\x00\t1
15\trestore admin notice\t2026-11-24\tt\t\\\\x00\t1
9\tserved key packages\t2026-11-10\tt\t\\\\x00\t1
\\.

";
    assert_eq!(
        run("newest_migration_in_dump_listing", &[], listing),
        "15\n"
    );
    assert_eq!(run("newest_migration_in_dump_listing", &[], ""), "0\n");
}
