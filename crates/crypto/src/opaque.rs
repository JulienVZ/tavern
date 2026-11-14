// SPDX-License-Identifier: AGPL-3.0-or-later

//! OPAQUE (RFC 9807) registration and login, through `opaque-ke`.
//!
//! The password never leaves the client, in any form. The server stores a
//! record from which the password cannot be read, and learns only whether a
//! login attempt succeeded.
//!
//! # Suite 1
//!
//! | Component | Choice |
//! |---|---|
//! | OPRF | ristretto255, SHA-512 |
//! | Key exchange | Triple-DH over ristretto255, SHA-512 |
//! | Key stretching | Argon2id, 128 MiB, 3 passes, 1 lane |
//! | Client identity | the canonical handle |
//! | Server identity | the server's OPAQUE public key (not its domain name) |
//!
//! The suite number is stored with each account ([`SUITE`]) so that the
//! parameters can evolve. Measurements behind the Argon2id parameters are in
//! `docs/adr/0003-opaque-authentication.md`.
//!
//! The handle is bound into the record, which is why a handle cannot be
//! changed without registering a new password.

use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::errors::{InternalError, ProtocolError};
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::{
    CipherSuite, ClientLoginFinishParameters, ClientRegistrationFinishParameters,
    CredentialFinalization, CredentialRequest, CredentialResponse, Identifiers,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, Ristretto255,
    ServerLoginParameters, TripleDh,
};
use rand::rngs::OsRng;
use sha2::Sha512;
use tavern_protocol::handle::Handle;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::secret::Secret;

/// Number of the suite implemented by this module, stored with each account.
pub const SUITE: u16 = 1;

/// Argon2id memory cost, in KiB (128 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 128 * 1024;
/// Argon2id number of passes.
pub const ARGON2_PASSES: u32 = 3;
/// Argon2id number of lanes.
pub const ARGON2_LANES: u32 = 1;

/// Length of the OPAQUE export key, in bytes.
pub const EXPORT_KEY_LEN: usize = 64;

/// Context string mixed into the key exchange transcript.
const CONTEXT: &[u8] = b"tavern opaque v1";

/// The OPAQUE cipher suite number 1.
struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Stretch;
}

/// Argon2id with the parameters of suite 1.
///
/// `opaque-ke` implements its key stretching trait for `Argon2` with that
/// crate's default parameters only, hence this wrapper. The construction is
/// the same as the upstream implementation: the OPRF output is the password
/// input and the salt is all zeros, which is sound because that input is
/// already unique per account and server.
#[derive(Default)]
struct Stretch;

impl Ksf for Stretch {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES, None)
            .map_err(|_| InternalError::KsfError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = GenericArray::default();
        argon2
            .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

fn identifiers(handle: &Handle) -> Identifiers<'_> {
    Identifiers {
        client: Some(handle.as_bytes()),
        server: None,
    }
}

fn malformed<T>(_: ProtocolError<T>) -> CryptoError {
    CryptoError::InvalidMessage
}

/// A password as typed by the user, normalised and erased on drop.
///
/// The text is normalised to Unicode NFKC so that the same password typed on
/// two operating systems, which may compose accented characters differently,
/// yields the same bytes. Nothing else is altered: no trimming, no case
/// change.
pub struct Password(Zeroizing<String>);

impl Password {
    /// Wraps what the user typed.
    pub fn new(typed: &str) -> Self {
        Self(Zeroizing::new(typed.nfkc().collect()))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// The OPAQUE export key: derived from the password on the client, never
/// known to the server. It protects the account identity key.
#[derive(Debug)]
pub struct ExportKey(Secret<EXPORT_KEY_LEN>);

impl ExportKey {
    pub(crate) fn secret(&self) -> &Secret<EXPORT_KEY_LEN> {
        &self.0
    }

    fn from_output(bytes: &[u8]) -> Result<Self, CryptoError> {
        Secret::from_slice(bytes)
            .map(Self)
            .ok_or(CryptoError::Internal)
    }
}

/// Client side.
pub mod client {
    use opaque_ke::{ClientLogin, ClientRegistration};

    use super::*;

    /// A registration in progress, between its two round trips.
    pub struct Registration(ClientRegistration<Suite>);

    /// What the client obtains when a registration completes.
    #[derive(Debug)]
    pub struct RegistrationOutput {
        /// The `RegistrationUpload` message to send to the server.
        pub upload: Vec<u8>,
        /// The export key for this password.
        pub export_key: ExportKey,
    }

    impl Registration {
        /// Starts a registration. Returns the state to keep and the
        /// `RegistrationRequest` message to send.
        pub fn start(password: &Password) -> Result<(Self, Vec<u8>), CryptoError> {
            let result = ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes())
                .map_err(|_| CryptoError::Internal)?;
            Ok((Self(result.state), result.message.serialize().to_vec()))
        }

        /// Completes a registration with the server's `RegistrationResponse`.
        ///
        /// This runs Argon2id: it takes a noticeable fraction of a second and
        /// 128 MiB of memory, and must not run on a user interface thread.
        pub fn finish(
            self,
            password: &Password,
            response: &[u8],
            handle: &Handle,
        ) -> Result<RegistrationOutput, CryptoError> {
            let response = RegistrationResponse::deserialize(response).map_err(malformed)?;
            let result = self
                .0
                .finish(
                    &mut OsRng,
                    password.as_bytes(),
                    response,
                    ClientRegistrationFinishParameters::new(identifiers(handle), None),
                )
                .map_err(|_| CryptoError::InvalidMessage)?;

            Ok(RegistrationOutput {
                upload: result.message.serialize().to_vec(),
                export_key: ExportKey::from_output(&result.export_key)?,
            })
        }
    }

    /// A login in progress, between its two round trips.
    pub struct Login(ClientLogin<Suite>);

    /// What the client obtains when a login succeeds.
    #[derive(Debug)]
    pub struct LoginOutput {
        /// The `CredentialFinalization` message to send to the server.
        pub finalization: Vec<u8>,
        /// The export key for this password.
        pub export_key: ExportKey,
    }

    impl Login {
        /// Starts a login. Returns the state to keep and the
        /// `CredentialRequest` message to send.
        pub fn start(password: &Password) -> Result<(Self, Vec<u8>), CryptoError> {
            let result = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes())
                .map_err(|_| CryptoError::Internal)?;
            Ok((Self(result.state), result.message.serialize().to_vec()))
        }

        /// Completes a login with the server's `CredentialResponse`.
        ///
        /// Fails with [`CryptoError::AuthenticationFailed`] when the password
        /// is wrong, when the account does not exist, or when the response was
        /// tampered with: the three cases are indistinguishable by design.
        ///
        /// This runs Argon2id; see [`Registration::finish`].
        pub fn finish(
            self,
            password: &Password,
            response: &[u8],
            handle: &Handle,
        ) -> Result<LoginOutput, CryptoError> {
            let response = CredentialResponse::deserialize(response).map_err(malformed)?;
            let result = self
                .0
                .finish(
                    &mut OsRng,
                    password.as_bytes(),
                    response,
                    ClientLoginFinishParameters::new(Some(CONTEXT), identifiers(handle), None),
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?;

            Ok(LoginOutput {
                finalization: result.message.serialize().to_vec(),
                export_key: ExportKey::from_output(&result.export_key)?,
            })
        }
    }
}

/// Server side. Nothing here runs Argon2id or sees a password.
pub mod server {
    use opaque_ke::{ServerLogin, ServerRegistration};

    use super::*;

    /// The instance's long-term OPAQUE secret.
    ///
    /// Losing it invalidates every password of the instance; it is generated
    /// once by `tavern-server gen-secrets` and must be backed up.
    pub struct ServerSetup(opaque_ke::ServerSetup<Suite>);

    impl ServerSetup {
        /// Generates a new setup.
        pub fn generate() -> Self {
            Self(opaque_ke::ServerSetup::<Suite>::new(&mut OsRng))
        }

        /// Serialises the setup. The result is secret.
        pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
            Zeroizing::new(self.0.serialize().to_vec())
        }

        /// Restores a setup serialised by [`ServerSetup::to_bytes`].
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
            opaque_ke::ServerSetup::<Suite>::deserialize(bytes)
                .map(Self)
                .map_err(malformed)
        }

        /// Answers a `RegistrationRequest` with a `RegistrationResponse`.
        ///
        /// Stateless, and its answer depends only on the setup, the handle and
        /// the request: it reveals nothing about whether the handle is taken.
        pub fn registration_start(
            &self,
            request: &[u8],
            handle: &Handle,
        ) -> Result<Vec<u8>, CryptoError> {
            let request = RegistrationRequest::deserialize(request).map_err(malformed)?;
            let result = ServerRegistration::<Suite>::start(&self.0, request, handle.as_bytes())
                .map_err(malformed)?;
            Ok(result.message.serialize().to_vec())
        }

        /// Starts a login. `record` is the account's stored record, or `None`
        /// when the handle is unknown.
        ///
        /// With `None` the response is computed from a decoy record. Its only
        /// repeatable part, the OPRF evaluation, is derived from the setup and
        /// the handle exactly as for a real account, so asking twice does not
        /// tell a real account from a missing one.
        pub fn login_start(
            &self,
            record: Option<&[u8]>,
            request: &[u8],
            handle: &Handle,
        ) -> Result<(LoginState, Vec<u8>), CryptoError> {
            let record = record
                .map(ServerRegistration::<Suite>::deserialize)
                .transpose()
                .map_err(|_| CryptoError::Internal)?;
            let request = CredentialRequest::deserialize(request).map_err(malformed)?;

            let result = ServerLogin::start(
                &mut OsRng,
                &self.0,
                record,
                request,
                handle.as_bytes(),
                ServerLoginParameters {
                    context: Some(CONTEXT),
                    identifiers: identifiers(handle),
                },
            )
            .map_err(malformed)?;

            let state = LoginState {
                login: result.state,
                handle: handle.clone(),
            };
            Ok((state, result.message.serialize().to_vec()))
        }
    }

    /// Turns a `RegistrationUpload` into the record to store for the account.
    ///
    /// The record is not secret in the way a password is, but it allows an
    /// offline guessing attack when combined with the [`ServerSetup`]; it is
    /// classified `AUTH` in the database schema.
    pub fn registration_finish(upload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let upload = RegistrationUpload::<Suite>::deserialize(upload).map_err(malformed)?;
        Ok(ServerRegistration::finish(upload).serialize().to_vec())
    }

    /// A login in progress on the server, between its two round trips.
    pub struct LoginState {
        login: ServerLogin<Suite>,
        handle: Handle,
    }

    impl LoginState {
        /// The handle this login was started for.
        pub fn handle(&self) -> &Handle {
            &self.handle
        }

        /// Verifies the client's `CredentialFinalization`.
        ///
        /// Succeeds only if the client knew the password of an existing
        /// account. A login started with a decoy record can never succeed.
        pub fn finish(self, finalization: &[u8]) -> Result<(), CryptoError> {
            let finalization =
                CredentialFinalization::deserialize(finalization).map_err(malformed)?;
            self.login
                .finish(
                    finalization,
                    ServerLoginParameters {
                        context: Some(CONTEXT),
                        identifiers: identifiers(&self.handle),
                    },
                )
                .map(|_| ())
                .map_err(|_| CryptoError::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::client::{Login, Registration};
    use super::server::{ServerSetup, registration_finish};
    use super::*;

    fn handle(text: &str) -> Handle {
        Handle::parse_canonical(text).unwrap()
    }

    /// Registers `handle` with `password`; returns the record and export key.
    fn register(setup: &ServerSetup, handle: &Handle, password: &str) -> (Vec<u8>, ExportKey) {
        let password = Password::new(password);
        let (state, request) = Registration::start(&password).unwrap();
        let response = setup.registration_start(&request, handle).unwrap();
        let output = state.finish(&password, &response, handle).unwrap();
        (
            registration_finish(&output.upload).unwrap(),
            output.export_key,
        )
    }

    /// Runs a full login; returns the client and server outcomes.
    fn login(
        setup: &ServerSetup,
        record: Option<&[u8]>,
        handle: &Handle,
        password: &str,
    ) -> (
        Result<ExportKey, CryptoError>,
        Option<Result<(), CryptoError>>,
    ) {
        let password = Password::new(password);
        let (client, request) = Login::start(&password).unwrap();
        let (server, response) = setup.login_start(record, &request, handle).unwrap();
        match client.finish(&password, &response, handle) {
            Ok(output) => {
                let outcome = server.finish(&output.finalization);
                (Ok(output.export_key), Some(outcome))
            }
            Err(error) => (Err(error), None),
        }
    }

    #[test]
    fn registration_then_login_yields_the_same_export_key() {
        let setup = ServerSetup::generate();
        let alice = handle("alice");
        let (record, registered_key) = register(&setup, &alice, "correct horse battery staple");

        let (client, server) = login(
            &setup,
            Some(&record),
            &alice,
            "correct horse battery staple",
        );

        assert!(client.unwrap().secret().ct_eq(registered_key.secret()));
        assert_eq!(server, Some(Ok(())));
    }

    #[test]
    fn a_wrong_password_fails_on_the_client() {
        let setup = ServerSetup::generate();
        let alice = handle("alice");
        let (record, _) = register(&setup, &alice, "correct horse battery staple");

        let (client, server) = login(&setup, Some(&record), &alice, "correct horse battery stapl");

        assert_eq!(client.unwrap_err(), CryptoError::AuthenticationFailed);
        assert!(server.is_none());
    }

    #[test]
    fn an_unknown_handle_fails_exactly_like_a_wrong_password() {
        let setup = ServerSetup::generate();

        let (client, _) = login(&setup, None, &handle("nobody"), "whatever password");

        assert_eq!(client.unwrap_err(), CryptoError::AuthenticationFailed);
    }

    #[test]
    fn a_record_is_bound_to_its_handle() {
        let setup = ServerSetup::generate();
        let (record, _) = register(&setup, &handle("alice"), "correct horse battery staple");

        let (client, _) = login(
            &setup,
            Some(&record),
            &handle("mallory"),
            "correct horse battery staple",
        );

        assert_eq!(client.unwrap_err(), CryptoError::AuthenticationFailed);
    }

    #[test]
    fn a_forged_finalization_is_rejected_by_the_server() {
        let setup = ServerSetup::generate();
        let alice = handle("alice");
        let (record, _) = register(&setup, &alice, "correct horse battery staple");

        let password = Password::new("correct horse battery staple");
        let (client, request) = Login::start(&password).unwrap();
        let (server, response) = setup.login_start(Some(&record), &request, &alice).unwrap();
        let mut finalization = client
            .finish(&password, &response, &alice)
            .unwrap()
            .finalization;
        finalization[0] ^= 1;

        assert_eq!(
            server.finish(&finalization),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn a_setup_survives_serialisation() {
        let setup = ServerSetup::generate();
        let alice = handle("alice");
        let (record, _) = register(&setup, &alice, "correct horse battery staple");

        let restored = ServerSetup::from_bytes(&setup.to_bytes()).unwrap();
        let (client, server) = login(
            &restored,
            Some(&record),
            &alice,
            "correct horse battery staple",
        );

        assert!(client.is_ok());
        assert_eq!(server, Some(Ok(())));
    }

    #[test]
    fn another_setup_cannot_log_anyone_in() {
        let alice = handle("alice");
        let (record, _) = register(
            &ServerSetup::generate(),
            &alice,
            "correct horse battery staple",
        );

        let (client, _) = login(
            &ServerSetup::generate(),
            Some(&record),
            &alice,
            "correct horse battery staple",
        );

        assert_eq!(client.unwrap_err(), CryptoError::AuthenticationFailed);
    }

    /// The first bytes of a `CredentialResponse` are the OPRF evaluation: the
    /// only part an observer can compare across two identical requests.
    #[test]
    fn repeated_requests_do_not_distinguish_real_and_missing_accounts() {
        const EVALUATION_LEN: usize = 32;
        let setup = ServerSetup::generate();
        let alice = handle("alice");
        let nobody = handle("nobody");
        let (record, _) = register(&setup, &alice, "correct horse battery staple");
        let (_, request) = Login::start(&Password::new("guess")).unwrap();

        let real_1 = setup
            .login_start(Some(&record), &request, &alice)
            .unwrap()
            .1;
        let real_2 = setup
            .login_start(Some(&record), &request, &alice)
            .unwrap()
            .1;
        let fake_1 = setup.login_start(None, &request, &nobody).unwrap().1;
        let fake_2 = setup.login_start(None, &request, &nobody).unwrap().1;

        // Same length, same stable prefix on repetition, in both cases.
        assert_eq!(real_1.len(), fake_1.len());
        assert_eq!(real_1[..EVALUATION_LEN], real_2[..EVALUATION_LEN]);
        assert_eq!(fake_1[..EVALUATION_LEN], fake_2[..EVALUATION_LEN]);
        // Everything after it is freshly randomised, in both cases.
        assert_ne!(real_1[EVALUATION_LEN..], real_2[EVALUATION_LEN..]);
        assert_ne!(fake_1[EVALUATION_LEN..], fake_2[EVALUATION_LEN..]);
        // And the stable part depends on the handle, not on the record.
        assert_ne!(real_1[..EVALUATION_LEN], fake_1[..EVALUATION_LEN]);
    }

    #[test]
    fn registration_response_does_not_depend_on_existing_accounts() {
        let setup = ServerSetup::generate();
        let alice = handle("alice");
        let (_, request) = Registration::start(&Password::new("some password")).unwrap();

        let before = setup.registration_start(&request, &alice).unwrap();
        register(&setup, &alice, "correct horse battery staple");
        let after = setup.registration_start(&request, &alice).unwrap();

        assert_eq!(before, after);
    }

    #[test]
    fn malformed_messages_are_rejected_without_panicking() {
        let setup = ServerSetup::generate();
        let alice = handle("alice");

        for garbage in [&[][..], &[0u8; 3], &[0xFF; 32], &[0u8; 500]] {
            assert!(setup.registration_start(garbage, &alice).is_err());
            assert!(setup.login_start(None, garbage, &alice).is_err());
            assert!(registration_finish(garbage).is_err());
        }
        assert!(ServerSetup::from_bytes(&[1, 2, 3]).is_err());
    }

    #[test]
    fn passwords_are_normalised_to_nfkc() {
        let setup = ServerSetup::generate();
        let alice = handle("alice");
        // "é" precomposed at registration, decomposed (e + combining acute) at login.
        let (record, _) = register(&setup, &alice, "caf\u{e9} au lait 2026");

        let (client, server) = login(&setup, Some(&record), &alice, "cafe\u{301} au lait 2026");

        assert!(client.is_ok());
        assert_eq!(server, Some(Ok(())));
    }

    /// Frozen: the bytes a typed password becomes. They can never change,
    /// or existing accounts could no longer log in. Unicode guarantees that
    /// the normalisation of assigned characters is stable across versions;
    /// this test catches anything else (a different form, trimming, a
    /// library that deviates).
    #[test]
    fn password_normalisation_is_frozen() {
        let vectors: &[(&str, &str, &[u8])] = &[
            (
                "ascii is untouched",
                "correct horse battery staple",
                &[
                    99, 111, 114, 114, 101, 99, 116, 32, 104, 111, 114, 115, 101, 32, 98, 97, 116,
                    116, 101, 114, 121, 32, 115, 116, 97, 112, 108, 101,
                ],
            ),
            ("precomposed e acute", "caf\u{e9}", &[99, 97, 102, 195, 169]),
            (
                "decomposed e acute",
                "cafe\u{301}",
                &[99, 97, 102, 195, 169],
            ),
            ("fi ligature", "\u{fb01}sh", &[102, 105, 115, 104]),
            (
                "full-width letters",
                "\u{ff21}\u{ff42}\u{ff43}",
                &[65, 98, 99],
            ),
            ("angstrom sign", "\u{212b}", &[195, 133]),
            ("circled digit", "\u{2460}", &[49]),
            ("no-break space", "a\u{a0}b", &[97, 32, 98]),
            (
                "half-width katakana with voiced mark",
                "\u{ff76}\u{ff9e}",
                &[227, 130, 172],
            ),
            ("dz digraph", "\u{1c6}", &[100, 197, 190]),
            (
                "sharp s is kept",
                "stra\u{df}e",
                &[115, 116, 114, 97, 195, 159, 101],
            ),
            ("dotted capital i is kept", "\u{130}", &[196, 176]),
            ("superscript two", "x\u{b2}", &[120, 50]),
            (
                "emoji is kept",
                "\u{1f37a} beer",
                &[240, 159, 141, 186, 32, 98, 101, 101, 114],
            ),
            (
                "case and spaces are kept",
                "  MiXed  ",
                &[32, 32, 77, 105, 88, 101, 100, 32, 32],
            ),
        ];

        for (name, typed, expected) in vectors {
            assert_eq!(Password::new(typed).as_bytes(), *expected, "{name}");
        }
        // Two spellings of the same text give the same bytes.
        assert_eq!(
            Password::new("caf\u{e9}").as_bytes(),
            Password::new("cafe\u{301}").as_bytes()
        );
    }

    #[test]
    fn passwords_are_not_trimmed_or_case_folded() {
        let setup = ServerSetup::generate();
        let alice = handle("alice");
        let (record, _) = register(&setup, &alice, "Correct Horse ");

        assert!(
            login(&setup, Some(&record), &alice, "Correct Horse")
                .0
                .is_err()
        );
        assert!(
            login(&setup, Some(&record), &alice, "correct horse ")
                .0
                .is_err()
        );
        assert!(
            login(&setup, Some(&record), &alice, "Correct Horse ")
                .0
                .is_ok()
        );
    }

    #[test]
    fn debug_output_of_secrets_is_redacted() {
        let setup = ServerSetup::generate();
        let (_, export_key) = register(&setup, &handle("alice"), "hunter2 hunter2");

        assert_eq!(
            format!("{:?}", Password::new("hunter2 hunter2")),
            "Password(<redacted>)"
        );
        assert!(format!("{export_key:?}").contains("redacted"));
    }
}
