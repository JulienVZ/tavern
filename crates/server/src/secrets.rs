// SPDX-License-Identifier: AGPL-3.0-or-later

//! Instance secrets.
//!
//! Each secret has exactly one purpose. They are generated once by
//! `tavern-server gen-secrets`, stored in the instance's `.env`, and must be
//! backed up with the database (see `docs/configuration.md`).

use data_encoding::BASE64URL_NOPAD;
use tavern_crypto::identity::ExternalSenderKey;
use tavern_crypto::opaque::server::ServerSetup;
use tavern_crypto::secret::Secret;

/// Environment variable names.
pub mod vars {
    /// OPAQUE server setup. Losing it invalidates every password.
    pub const OPAQUE_SERVER_SETUP: &str = "TAVERN_OPAQUE_SERVER_SETUP";
    /// Seed of the dedicated MLS external sender key.
    pub const MLS_EXTERNAL_SENDER_KEY: &str = "TAVERN_MLS_EXTERNAL_SENDER_KEY";
    /// Key that encrypts TOTP secrets at rest.
    pub const TOTP_ENCRYPTION_KEY: &str = "TAVERN_TOTP_ENCRYPTION_KEY";
    /// Key that derives decoy answers for unknown handles.
    pub const HANDLE_PRIVACY_KEY: &str = "TAVERN_HANDLE_PRIVACY_KEY";

    /// Every secret, in the order `gen-secrets` prints them.
    pub const ALL: [&str; 4] = [
        OPAQUE_SERVER_SETUP,
        MLS_EXTERNAL_SENDER_KEY,
        TOTP_ENCRYPTION_KEY,
        HANDLE_PRIVACY_KEY,
    ];
}

/// The secrets of an instance, decoded.
pub struct InstanceSecrets {
    /// OPAQUE server setup.
    pub opaque: ServerSetup,
    /// MLS external sender key. Only its public half is used at milestone M1.
    pub external_sender: ExternalSenderKey,
    /// Key that encrypts TOTP secrets at rest.
    pub totp_key: Secret<32>,
    /// Key that derives decoy answers for unknown handles.
    pub handle_privacy_key: Secret<32>,
}

impl std::fmt::Debug for InstanceSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstanceSecrets(<redacted>)")
    }
}

/// A secret is missing or malformed. The message never contains a value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretsError {
    /// The variable is not set.
    #[error(
        "the instance secret {0} is not set. Run `./scripts/init.sh` in deploy/ (it calls \
         `tavern-server gen-secrets`), or restore the .env that belongs to this database."
    )]
    Missing(&'static str),
    /// The variable does not decode to a valid secret.
    #[error(
        "the instance secret {0} is malformed. Restore it from your backup; do not generate a \
         new one on an instance that already has accounts."
    )]
    Invalid(&'static str),
}

fn decode(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<Vec<u8>, SecretsError> {
    let raw = lookup(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(SecretsError::Missing(name))?;
    BASE64URL_NOPAD
        .decode(raw.as_bytes())
        .map_err(|_| SecretsError::Invalid(name))
}

fn decode_key(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<Secret<32>, SecretsError> {
    Secret::from_slice(&decode(lookup, name)?).ok_or(SecretsError::Invalid(name))
}

impl InstanceSecrets {
    /// Reads the secrets from the process environment.
    pub fn from_env() -> Result<Self, SecretsError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Reads the secrets through `lookup`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, SecretsError> {
        let opaque = ServerSetup::from_bytes(&decode(&lookup, vars::OPAQUE_SERVER_SETUP)?)
            .map_err(|_| SecretsError::Invalid(vars::OPAQUE_SERVER_SETUP))?;
        let external_sender =
            ExternalSenderKey::from_seed(&decode_key(&lookup, vars::MLS_EXTERNAL_SENDER_KEY)?);

        Ok(Self {
            opaque,
            external_sender,
            totp_key: decode_key(&lookup, vars::TOTP_ENCRYPTION_KEY)?,
            handle_privacy_key: decode_key(&lookup, vars::HANDLE_PRIVACY_KEY)?,
        })
    }

    /// Generates a complete, fresh set of secrets as `(variable, value)` pairs.
    pub fn generate() -> Vec<(&'static str, String)> {
        let encode = |bytes: &[u8]| BASE64URL_NOPAD.encode(bytes);
        vec![
            (
                vars::OPAQUE_SERVER_SETUP,
                encode(&ServerSetup::generate().to_bytes()),
            ),
            (
                vars::MLS_EXTERNAL_SENDER_KEY,
                encode(ExternalSenderKey::generate().seed().expose()),
            ),
            (
                vars::TOTP_ENCRYPTION_KEY,
                encode(Secret::<32>::random().expose()),
            ),
            (
                vars::HANDLE_PRIVACY_KEY,
                encode(Secret::<32>::random().expose()),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn generated() -> HashMap<String, String> {
        InstanceSecrets::generate()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect()
    }

    #[test]
    fn generated_secrets_load_back() {
        let map = generated();

        let secrets = InstanceSecrets::from_lookup(|name| map.get(name).cloned()).unwrap();

        assert_eq!(map.len(), vars::ALL.len());
        assert_eq!(secrets.external_sender.public_bytes().len(), 32);
    }

    #[test]
    fn every_secret_is_distinct() {
        let map = generated();
        let mut values: Vec<&String> = map.values().collect();
        values.sort();
        values.dedup();

        assert_eq!(values.len(), vars::ALL.len());
        assert_ne!(
            generated()[vars::TOTP_ENCRYPTION_KEY],
            map[vars::TOTP_ENCRYPTION_KEY]
        );
    }

    #[test]
    fn each_missing_secret_is_named() {
        for name in vars::ALL {
            let mut map = generated();
            map.remove(name);

            let error = InstanceSecrets::from_lookup(|n| map.get(n).cloned()).unwrap_err();

            assert_eq!(error, SecretsError::Missing(name));
            assert!(error.to_string().contains("init.sh"));
        }
    }

    #[test]
    fn malformed_secrets_are_rejected_without_echoing_them() {
        for name in vars::ALL {
            for bad in ["not base64 !", "AAAA", "c2hvcnQ"] {
                let mut map = generated();
                map.insert(name.to_owned(), bad.to_owned());

                let error = InstanceSecrets::from_lookup(|n| map.get(n).cloned()).unwrap_err();

                assert_eq!(error, SecretsError::Invalid(name), "{name} = {bad}");
                assert!(!error.to_string().contains(bad));
            }
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let map = generated();
        let secrets = InstanceSecrets::from_lookup(|name| map.get(name).cloned()).unwrap();

        assert_eq!(format!("{secrets:?}"), "InstanceSecrets(<redacted>)");
    }
}
