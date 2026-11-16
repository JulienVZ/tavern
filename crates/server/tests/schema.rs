// SPDX-License-Identifier: AGPL-3.0-or-later

//! Checks that every database column is classified in
//! `docs/database-schema.md`, so that no column can be added without stating
//! what kind of data it holds.
//!
//! Needs PostgreSQL, like `tests/http.rs`:
//!
//! ```sh
//! TAVERN_TEST_DATABASE_URL=postgres://... cargo test -p tavern-server -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers panic on set-up failure"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use tavern_server::db;

const SCHEMA_DOC: &str = include_str!("../../../docs/database-schema.md");
const CLASSES: &[&str] = &["META", "PUB", "HASH", "AUTH", "WRAP", "E2EE", "SRV", "HALF"];

/// Extracts `table -> {column -> class}` from the SQL blocks of the document.
fn documented_columns() -> BTreeMap<String, BTreeMap<String, String>> {
    let mut tables: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<String> = None;

    for line in SCHEMA_DOC.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("CREATE TABLE ") {
            let name = rest.split_whitespace().next().unwrap().to_owned();
            tables.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        if trimmed.starts_with(");") {
            current = None;
            continue;
        }
        let Some(table) = &current else { continue };
        let Some((definition, comment)) = trimmed.split_once("--") else {
            continue;
        };
        let Some(column) = definition.split_whitespace().next() else {
            continue;
        };
        let class = comment.split_whitespace().next().unwrap_or_default();
        if CLASSES.contains(&class) {
            tables
                .get_mut(table)
                .unwrap()
                .insert(column.to_owned(), class.to_owned());
        }
    }
    tables
}

#[test]
fn document_parser_finds_the_account_tables() {
    let documented = documented_columns();

    assert_eq!(documented["users"]["opaque_record"], "AUTH");
    assert_eq!(documented["sessions"]["token_hash"], "HASH");
    assert_eq!(documented["devices"]["name_encrypted"], "E2EE");
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn every_database_column_is_classified() {
    let database_url = common::database_url();
    let pool = db::connect(&database_url, 1).await.unwrap();
    db::migrate(&pool).await.unwrap();

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations' \
         ORDER BY table_name, ordinal_position",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!rows.is_empty(), "the migrations created no table");

    let mut actual: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (table, column) in rows {
        actual.entry(table).or_default().insert(column);
    }

    let documented = documented_columns();
    let mut problems = Vec::new();
    for (table, columns) in &actual {
        let Some(classified) = documented.get(table) else {
            problems.push(format!(
                "table {table} is not described in docs/database-schema.md"
            ));
            continue;
        };
        for column in columns {
            if !classified.contains_key(column) {
                problems.push(format!(
                    "{table}.{column} exists but has no class in the document"
                ));
            }
        }
        for column in classified.keys() {
            if !columns.contains(column) {
                problems.push(format!("{table}.{column} is documented but does not exist"));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "schema and documentation differ:\n{}",
        problems.join("\n")
    );
}
