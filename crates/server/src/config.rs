// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server configuration, read from environment variables only.
//!
//! Every variable is documented in `docs/configuration.md` and in
//! `deploy/.env.example`.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

/// Environment variable names.
pub mod vars {
    /// Address the HTTP server binds to.
    pub const LISTEN_ADDR: &str = "TAVERN_LISTEN_ADDR";
    /// PostgreSQL connection URL. Secret.
    pub const DATABASE_URL: &str = "TAVERN_DATABASE_URL";
    /// Upper bound of the connection pool.
    pub const DB_MAX_CONNECTIONS: &str = "TAVERN_DB_MAX_CONNECTIONS";
    /// Whether migrations run at start-up.
    pub const RUN_MIGRATIONS: &str = "TAVERN_RUN_MIGRATIONS";
    /// `tracing` filter directive.
    pub const LOG_LEVEL: &str = "TAVERN_LOG_LEVEL";
    /// Log output format.
    pub const LOG_FORMAT: &str = "TAVERN_LOG_FORMAT";
    /// Public URL of this instance's source code.
    pub const SOURCE_URL: &str = "TAVERN_SOURCE_URL";
    /// Whether the last `X-Forwarded-For` entry is the client address.
    pub const TRUST_FORWARDED_FOR: &str = "TAVERN_TRUST_FORWARDED_FOR";
    /// Days an unused session stays valid.
    pub const SESSION_TTL_DAYS: &str = "TAVERN_SESSION_TTL_DAYS";
}

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_SESSION_TTL_DAYS: u64 = 90;
const MAX_SESSION_TTL_DAYS: u64 = 3650;

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable lines.
    Text,
    /// One JSON object per line.
    Json,
}

/// Validated server configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub listen_addr: SocketAddr,
    /// PostgreSQL connection URL. Never logged.
    pub database_url: String,
    /// Upper bound of the connection pool.
    pub db_max_connections: u32,
    /// Whether migrations run at start-up.
    pub run_migrations: bool,
    /// `tracing` filter directive, e.g. `info` or `tavern_server=debug,info`.
    pub log_level: String,
    /// Log output format.
    pub log_format: LogFormat,
    /// Public URL of this instance's source code, exposed by `GET /version`.
    pub source_url: Option<String>,
    /// Whether requests arrive through a reverse proxy that appends the client
    /// address to `X-Forwarded-For`. Only enable behind such a proxy.
    pub trust_forwarded_for: bool,
    /// How long an unused session stays valid.
    pub session_ttl: Duration,
}

// Manual implementation so that the database URL, which contains a password,
// cannot end up in logs through `{:?}`.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen_addr", &self.listen_addr)
            .field("database_url", &"<redacted>")
            .field("db_max_connections", &self.db_max_connections)
            .field("run_migrations", &self.run_migrations)
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("source_url", &self.source_url)
            .field("trust_forwarded_for", &self.trust_forwarded_for)
            .field("session_ttl", &self.session_ttl)
            .finish()
    }
}

/// A configuration variable is missing or malformed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A required variable is not set.
    #[error("environment variable {0} is required")]
    Missing(&'static str),
    /// A variable is set to a value that cannot be used.
    #[error("environment variable {name} is invalid: {reason}")]
    Invalid {
        /// Variable name.
        name: &'static str,
        /// What is wrong with the value. Never contains the value of a secret.
        reason: String,
    },
}

impl Config {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Reads the configuration through `lookup`, which returns the value of a
    /// variable or `None` when it is unset. Empty values count as unset.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |name: &str| {
            lookup(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let listen_addr = get(vars::LISTEN_ADDR)
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned())
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::Invalid {
                name: vars::LISTEN_ADDR,
                reason: e.to_string(),
            })?;

        let database_url =
            get(vars::DATABASE_URL).ok_or(ConfigError::Missing(vars::DATABASE_URL))?;
        if !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")) {
            return Err(ConfigError::Invalid {
                name: vars::DATABASE_URL,
                reason: "must start with postgres:// or postgresql://".to_owned(),
            });
        }

        let db_max_connections = match get(vars::DB_MAX_CONNECTIONS) {
            None => DEFAULT_DB_MAX_CONNECTIONS,
            Some(raw) => match raw.parse::<u32>() {
                Ok(n) if n > 0 => n,
                _ => {
                    return Err(ConfigError::Invalid {
                        name: vars::DB_MAX_CONNECTIONS,
                        reason: "must be a positive integer".to_owned(),
                    });
                }
            },
        };

        let run_migrations = match get(vars::RUN_MIGRATIONS) {
            None => true,
            Some(raw) => parse_bool(&raw).ok_or_else(|| ConfigError::Invalid {
                name: vars::RUN_MIGRATIONS,
                reason: "must be true or false".to_owned(),
            })?,
        };

        let log_format = match get(vars::LOG_FORMAT).as_deref() {
            None | Some("text") => LogFormat::Text,
            Some("json") => LogFormat::Json,
            Some(_) => {
                return Err(ConfigError::Invalid {
                    name: vars::LOG_FORMAT,
                    reason: "must be text or json".to_owned(),
                });
            }
        };

        let trust_forwarded_for = match get(vars::TRUST_FORWARDED_FOR) {
            None => false,
            Some(raw) => parse_bool(&raw).ok_or_else(|| ConfigError::Invalid {
                name: vars::TRUST_FORWARDED_FOR,
                reason: "must be true or false".to_owned(),
            })?,
        };

        let session_ttl_days = match get(vars::SESSION_TTL_DAYS) {
            None => DEFAULT_SESSION_TTL_DAYS,
            Some(raw) => match raw.parse::<u64>() {
                Ok(days) if (1..=MAX_SESSION_TTL_DAYS).contains(&days) => days,
                _ => {
                    return Err(ConfigError::Invalid {
                        name: vars::SESSION_TTL_DAYS,
                        reason: "must be a number of days between 1 and 3650".to_owned(),
                    });
                }
            },
        };

        Ok(Self {
            listen_addr,
            database_url,
            db_max_connections,
            run_migrations,
            log_level: get(vars::LOG_LEVEL).unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_owned()),
            log_format,
            source_url: get(vars::SOURCE_URL),
            trust_forwarded_for,
            session_ttl: Duration::from_secs(session_ttl_days * 24 * 60 * 60),
        })
    }
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config_from(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_lookup(|name| map.get(name).cloned())
    }

    const DB: (&str, &str) = (vars::DATABASE_URL, "postgres://tavern:pw@db/tavern");

    #[test]
    fn defaults_apply_when_only_database_url_is_set() {
        let config = config_from(&[DB]).unwrap();

        assert_eq!(config.listen_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.db_max_connections, 10);
        assert!(config.run_migrations);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_format, LogFormat::Text);
        assert_eq!(config.source_url, None);
        assert!(!config.trust_forwarded_for);
        assert_eq!(config.session_ttl, Duration::from_secs(90 * 24 * 60 * 60));
    }

    #[test]
    fn database_url_is_required() {
        assert_eq!(
            config_from(&[]),
            Err(ConfigError::Missing(vars::DATABASE_URL))
        );
        assert_eq!(
            config_from(&[(vars::DATABASE_URL, "  ")]),
            Err(ConfigError::Missing(vars::DATABASE_URL))
        );
    }

    #[test]
    fn database_url_must_be_postgres() {
        let err = config_from(&[(vars::DATABASE_URL, "mysql://x")]).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: vars::DATABASE_URL,
                ..
            }
        ));
    }

    #[test]
    fn overrides_are_parsed() {
        let config = config_from(&[
            DB,
            (vars::LISTEN_ADDR, "127.0.0.1:9000"),
            (vars::DB_MAX_CONNECTIONS, "3"),
            (vars::RUN_MIGRATIONS, "false"),
            (vars::LOG_LEVEL, "debug"),
            (vars::LOG_FORMAT, "json"),
            (vars::SOURCE_URL, "https://example.org/src"),
            (vars::TRUST_FORWARDED_FOR, "true"),
            (vars::SESSION_TTL_DAYS, "7"),
        ])
        .unwrap();

        assert_eq!(config.listen_addr, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.db_max_connections, 3);
        assert!(!config.run_migrations);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.log_format, LogFormat::Json);
        assert_eq!(
            config.source_url.as_deref(),
            Some("https://example.org/src")
        );
    }

    #[test]
    fn invalid_values_are_rejected() {
        for (name, value) in [
            (vars::LISTEN_ADDR, "not-an-address"),
            (vars::DB_MAX_CONNECTIONS, "0"),
            (vars::RUN_MIGRATIONS, "maybe"),
            (vars::LOG_FORMAT, "xml"),
            (vars::TRUST_FORWARDED_FOR, "perhaps"),
            (vars::SESSION_TTL_DAYS, "0"),
            (vars::SESSION_TTL_DAYS, "forever"),
        ] {
            let err = config_from(&[DB, (name, value)]).unwrap_err();
            assert!(
                matches!(err, ConfigError::Invalid { name: n, .. } if n == name),
                "{name}"
            );
        }
    }

    #[test]
    fn debug_output_redacts_the_database_url() {
        let config = config_from(&[DB]).unwrap();
        let debug = format!("{config:?}");

        assert!(!debug.contains("pw@db"));
        assert!(debug.contains("<redacted>"));
    }
}
