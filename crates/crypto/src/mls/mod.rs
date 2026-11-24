// SPDX-License-Identifier: AGPL-3.0-or-later

//! MLS (RFC 9420) through OpenMLS 0.9, as decided in ADR 0002 and ADR 0019.
//!
//! The client core and the server use this module, never OpenMLS directly.
//! It fixes the parameters of every group (section 1 of ADR 0019), checks
//! every leaf against the device certificates and the identity keys the
//! caller trusts (section 2), builds and validates KeyPackages (3), applies
//! the client's policy on incoming handshake messages (6, 11), pads content
//! (8), and computes safety numbers (10).
//!
//! What it does not do: store the group state (the caller's
//! [`openmls_traits::storage::StorageProvider`], ADR 0019 sections 13 and
//! 14), order or deliver messages (the server), decide who may join a
//! conversation (the caller's [`Roster`]).

pub mod credential;
pub mod group;
pub mod group_id;
pub mod key_package;
mod no_storage;
pub mod padding;
mod policy;
pub mod public;
pub mod safety_number;
mod signer;

use openmls::prelude::{
    Capabilities, Ciphersuite, CredentialType, Extension, ExtensionType, Extensions,
    ExternalSender, MlsGroupCreateConfig, MlsGroupJoinConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    RequiredCapabilitiesExtension, SenderRatchetConfiguration,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};

pub use credential::{LeafError, Roster, VerifiedLeaf};
pub use group::{Commit, ExpectedGroup, Group, Incoming, Joined, MembershipChanges, Plaintext};
pub use key_package::ClaimedKeyPackage;
pub use policy::{Alarm, PolicyError};
pub use public::{
    ApplicationHeader, CommitHeader, MergedCommit, PROPOSAL_QUEUE_KIND, PublicEntries, PublicState,
    Reissued, ValidatedCommit, application_header, commit_header, first_commit_sender,
    is_external_commit, welcome_key_packages,
};
pub use signer::{DeviceSigner, ServerSigner};

/// The only ciphersuite of Tavern's groups.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// OpenMLS pads the content of a `PrivateMessage` to a multiple of this; the
/// size buckets of [`padding`] are multiples of it.
pub const PADDING_SIZE: usize = 256;
/// Past epochs whose secrets are kept: none. The server accepts application
/// messages for the current epoch only and every device processes the
/// sequence in order, so nothing ever needs an older epoch (section 9).
pub const MAX_PAST_EPOCHS: usize = 0;
/// Messages of one sender that may arrive out of order within an epoch.
pub const OUT_OF_ORDER_TOLERANCE: u32 = 16;
/// How far ahead of the last message of a sender a message may be.
pub const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;
/// A device commits an update of its own leaf after this many days...
pub const UPDATE_INTERVAL_DAYS: u64 = 7;
/// ...or after sending this many messages in the conversation, whichever
/// comes first (applied by the client's sync engine).
pub const UPDATE_AFTER_MESSAGES: u32 = 100;

/// Something MLS-related failed.
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// A commit or a Welcome accepted by the server breaks the rules: the
    /// conversation must be marked broken, with the alarm of section 11.
    /// See [`MlsError::is_alarm`].
    #[error("alarm: {0}")]
    Alarm(#[from] Alarm),
    /// A leaf this device was about to add is not acceptable (section 2).
    #[error("a device's certificate is not acceptable: {0}")]
    Leaf(#[from] LeafError),
    /// A proposal received on its own, or an operation of this device, is
    /// refused by Tavern's policy (section 6). A refused proposal is dropped.
    #[error("refused by the group policy: {0}")]
    Policy(#[from] PolicyError),
    /// OpenMLS refused the message.
    #[error("refused message: {0}")]
    Refused(Refusal),
    /// A commit of the conversation's sequence, for this device's epoch, that
    /// OpenMLS cannot process although the server accepted it: this device's
    /// group state no longer matches the other devices' (a lost write, a
    /// commit merged that the others never saw). Not an alarm: the device
    /// resyncs by external commit, as the same device (section 5), and the
    /// conversation is marked broken (section 11) only if that fails. See
    /// [`MlsError::is_out_of_sync`].
    #[error("this device is out of sync with the group: {0}")]
    OutOfSync(String),
    /// The server has asked to remove this very device from the group: it
    /// commits nothing more there (a commit cannot remove its committer, and
    /// one without the removal would drop it). Another member commits it;
    /// this device then learns it was removed (`self_removed`), and rejoins
    /// by external commit if it is still active (section 15).
    #[error("the server asked to remove this device from the group")]
    BeingRemoved,
    /// On the server: a member's commit leaves out a removal the server
    /// asked for. Refused with `REMOVAL_PENDING`: the member commits again,
    /// with it (section 6).
    #[error("the commit leaves out a removal the server asked for")]
    RemovalPending,
    /// On the server: the commit is not the submitting device's own (it is
    /// signed by another leaf, or joins another device).
    #[error("the commit is not the submitting device's own")]
    WrongSender,
    /// On the server: the GroupInfo submitted with a commit is not the one
    /// of its new epoch with its ratchet tree, signed by the committer.
    #[error("the GroupInfo is not the new epoch's, signed by the committer")]
    GroupInfo,
    /// On the server: OpenMLS finds the message invalid against the group's
    /// public state (signature, proposals, path...). OpenMLS's message,
    /// which carries no secret.
    #[error("invalid against the group's public state: {0}")]
    Invalid(String),
    /// The padded content is malformed.
    #[error("malformed padding: {0}")]
    Padding(#[from] padding::PaddingError),
    /// The bytes are not a well-formed MLS message of the expected kind.
    #[error("malformed or unexpected MLS message")]
    Malformed,
    /// The group is not one of Tavern's: other ciphersuite, other external
    /// sender, other required capabilities, other group id format.
    #[error("the group does not follow Tavern's parameters")]
    Parameters,
    /// Not the group this device expected: another conversation or
    /// generation (an old Welcome replayed), or not the expected
    /// participants.
    #[error("not the expected group")]
    UnexpectedGroup,
    /// OpenMLS refused or failed. Its errors carry no secret.
    #[error("MLS: {0}")]
    Library(String),
}

impl MlsError {
    /// Whether this must raise the alarm of section 11: a leaf that is not a
    /// verified device of a participant, a policy violation in a commit the
    /// server accepted, a commit that refers to a refused proposal, or a
    /// commit the server should have refused.
    pub fn is_alarm(&self) -> bool {
        matches!(self, Self::Alarm(_))
    }

    /// Whether this device must resync by external commit (section 11): it
    /// cannot process a commit the server accepted.
    pub fn is_out_of_sync(&self) -> bool {
        matches!(self, Self::OutOfSync(_))
    }
}

/// Why OpenMLS refused an incoming message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// For a later epoch: this device has not processed a commit yet.
    #[error("the message is for a later epoch")]
    WrongEpoch,
    /// For a past epoch, whose secrets are deleted (section 9): the sender
    /// re-encrypts and resends (`STALE_EPOCH`, section 7).
    #[error("the message is for a past epoch")]
    PastEpoch,
    /// For another group.
    #[error("the message is for another group")]
    WrongGroup,
    /// The signature does not verify.
    #[error("the signature does not verify")]
    InvalidSignature,
    /// From an external sender the group does not list.
    #[error("the external sender is not the group's")]
    UnauthorizedExternalSender,
    /// Already read: its key was deleted once used (section 9).
    #[error("the message was already read")]
    AlreadyRead,
    /// Cannot be decrypted: too far from the sender's last message, or
    /// tampered with.
    #[error("the message cannot be decrypted")]
    UnableToDecrypt,
    /// From a leaf that is not in the group.
    #[error("the sender is not a member")]
    UnknownMember,
}

pub(crate) fn library(error: impl std::fmt::Display) -> MlsError {
    MlsError::Library(error.to_string())
}

/// Classifies OpenMLS's refusal of an incoming message.
pub(crate) fn processing_error<E: std::fmt::Display>(
    error: openmls::prelude::ProcessMessageError<E>,
) -> MlsError {
    use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
    use openmls::prelude::{ProcessMessageError as P, StageCommitError, ValidationError as V};
    match error {
        P::InvalidCommit(StageCommitError::MissingProposal) => Alarm::UnknownProposal.into(),
        P::ValidationError(V::WrongEpoch) => MlsError::Refused(Refusal::WrongEpoch),
        // A `PublicMessage` of a past epoch, and a `PrivateMessage` of an
        // epoch whose secrets are deleted (section 9).
        P::ValidationError(
            V::NoPastEpochData
            | V::UnableToDecrypt(MessageDecryptionError::SecretTreeError(
                SecretTreeError::TooDistantInThePast,
            )),
        ) => MlsError::Refused(Refusal::PastEpoch),
        P::ValidationError(V::WrongGroupId) => MlsError::Refused(Refusal::WrongGroup),
        P::ValidationError(V::InvalidSignature) => MlsError::Refused(Refusal::InvalidSignature),
        P::ValidationError(V::UnauthorizedExternalSender) => {
            MlsError::Refused(Refusal::UnauthorizedExternalSender)
        }
        P::ValidationError(V::UnableToDecrypt(MessageDecryptionError::SecretTreeError(
            SecretTreeError::SecretReuseError,
        ))) => MlsError::Refused(Refusal::AlreadyRead),
        P::ValidationError(V::UnableToDecrypt(_)) => MlsError::Refused(Refusal::UnableToDecrypt),
        P::ValidationError(V::UnknownMember) => MlsError::Refused(Refusal::UnknownMember),
        // A proposal from a joining device other than an `Add`.
        P::UnsupportedProposalType => PolicyError::ExternalJoinProposal.into(),
        other => library(other),
    }
}

/// What OpenMLS's refusal of a commit of the conversation's sequence means
/// (section 11). The commit is for this group and this epoch (the wrapper
/// checks that first), and the server accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitFault {
    /// Checkable on the group's public state, which the server holds and
    /// validates commits against, or explained by no state of this device:
    /// the server accepted an invalid commit. Also every error not reviewed
    /// here: the matches below are exhaustive, so a new OpenMLS variant
    /// fails to compile until it is classified.
    Alarm,
    /// The commit refers to a proposal this device refused or never
    /// received: an alarm too.
    UnknownProposal,
    /// Depends on what only this device holds (its secrets, its pending
    /// commit, its own view of the group context): it may be out of sync.
    OutOfSync,
    /// This device's own trouble: its storage, a bug, a group it has left.
    Local,
    /// Another group or epoch, which the wrapper rules out before OpenMLS.
    Refused(Refusal),
}

impl CommitFault {
    fn of<E>(error: &openmls::prelude::ProcessMessageError<E>) -> Self {
        use openmls::prelude::ProcessMessageError as P;
        match error {
            P::LibraryError(_) | P::StorageError(_) | P::GroupStateError(_) => Self::Local,
            // The wire format and the sender are public: the server sees them.
            P::IncompatibleWireFormat
            | P::UnauthorizedExternalApplicationMessage
            | P::UnauthorizedExternalCommitMessage
            | P::UnsupportedProposalType => Self::Alarm,
            P::ValidationError(error) => Self::of_validation(error),
            P::InvalidCommit(error) => Self::of_staging(error),
        }
    }

    fn of_validation(error: &openmls::prelude::ValidationError) -> Self {
        use openmls::prelude::ValidationError as V;
        match error {
            V::LibraryError(_) => Self::Local,
            V::WrongGroupId => Self::Refused(Refusal::WrongGroup),
            V::WrongEpoch => Self::Refused(Refusal::WrongEpoch),
            V::NoPastEpochData => Self::Refused(Refusal::PastEpoch),
            // The membership tag is computed with the epoch's membership key,
            // a secret the server does not have; the signed content includes
            // the group context as this device holds it. A device whose state
            // forked fails both, while the server verified the signature
            // against the true context.
            V::InvalidMembershipTag | V::InvalidSignature => Self::OutOfSync,
            // Framing, senders, leaves, KeyPackages, extensions: all public.
            // A commit is never encrypted, so it cannot fail to decrypt.
            V::NotACommit
            | V::NotAnExternalAddProposal
            | V::NoPath
            | V::UnencryptedApplicationMessage
            | V::UnknownMember
            | V::MissingMembershipTag
            | V::MissingConfirmationTag
            | V::WrongWireFormat
            | V::NonMemberApplicationMessage
            | V::UnableToDecrypt(_)
            | V::UnauthorizedExternalSender
            | V::NoExternalSendersExtension
            | V::KeyPackageVerifyError(_)
            | V::UpdatePathError(_)
            | V::InvalidLeafNodeSignature
            | V::InvalidLeafNodeSourceType
            | V::InvalidSenderType
            | V::CommitterIncludedOwnUpdate
            | V::InvalidAddProposalCiphersuite
            | V::ExternalCommitValidation(_)
            | V::InvalidExtension(_) => Self::Alarm,
        }
    }

    fn of_staging(error: &openmls::prelude::StageCommitError) -> Self {
        use openmls::prelude::StageCommitError as S;
        match error {
            S::LibraryError(_) => Self::Local,
            S::EpochMismatch => Self::Refused(Refusal::WrongEpoch),
            S::MissingProposal => Self::UnknownProposal,
            // The new epoch's secrets, this device's private keys and its own
            // pending commit: only this device has them.
            S::ConfirmationTagMismatch
            | S::OwnCommitMismatch
            | S::OwnKeyNotFound
            | S::MissingDecryptionKey => Self::OutOfSync,
            S::UpdatePathError(error) => Self::of_path(error),
            // Proposals, path leaves, PSKs (which Tavern never uses), senders:
            // all checkable on the public state.
            S::WrongPlaintextContentType
            | S::PathLeafNodeVerificationFailure
            | S::RequiredPathNotFound
            | S::ConfirmationTagMissing
            | S::AttemptedSelfRemoval
            | S::InconsistentSenderIndex
            | S::SenderTypeExternal
            | S::SenderTypeNewMemberProposal
            | S::TooManyNewMembers
            | S::ProposalValidationError(_)
            | S::PskError(_)
            | S::ExternalCommitValidation(_)
            | S::VerifiedUpdatePathError(_)
            | S::GroupContextExtensionsProposalValidationError(_)
            | S::LeafNodeValidation(_)
            | S::DuplicatePskId(_) => Self::Alarm,
        }
    }

    fn of_path(error: &openmls::prelude::ApplyUpdatePathError) -> Self {
        use openmls::prelude::ApplyUpdatePathError as A;
        match error {
            A::LibraryError(_) => Self::Local,
            // What this device decrypts with its own keys, and its own leaf.
            A::UnableToDecrypt | A::PathMismatch | A::MissingOwnLeaf => Self::OutOfSync,
            // The path's shape and public keys.
            A::PathLengthMismatch
            | A::ParentHashMismatch
            | A::MissingParentHash
            | A::MissingSender
            | A::TreeFull
            | A::InconsistentSenderIndex
            | A::MissingCiphertext => Self::Alarm,
        }
    }
}

/// Classifies OpenMLS's refusal of a commit of the conversation's sequence
/// ([`CommitFault`]).
pub(crate) fn commit_processing_error<E: std::fmt::Display>(
    error: openmls::prelude::ProcessMessageError<E>,
) -> MlsError {
    match CommitFault::of(&error) {
        CommitFault::Alarm => Alarm::InvalidCommit(error.to_string()).into(),
        CommitFault::UnknownProposal => Alarm::UnknownProposal.into(),
        CommitFault::OutOfSync => MlsError::OutOfSync(error.to_string()),
        CommitFault::Local => library(error),
        CommitFault::Refused(refusal) => MlsError::Refused(refusal),
    }
}

/// What OpenMLS needs: RustCrypto for the crypto and the randomness, and the
/// caller's storage (the encrypted local store on a client).
#[derive(Debug, Default)]
pub struct Provider<S> {
    crypto: RustCrypto,
    storage: S,
}

impl<S> Provider<S> {
    /// A provider over `storage`.
    pub fn new(storage: S) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl<S: StorageProvider<CURRENT_VERSION>> OpenMlsProvider for Provider<S> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = S;

    fn storage(&self) -> &S {
        &self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

/// The group context extensions of every Tavern group: the server as the
/// only external sender, and basic credentials required.
fn group_context_extensions(
    external_sender: &[u8; crate::identity::PUBLIC_KEY_LEN],
) -> Result<Extensions<openmls::prelude::GroupContext>, MlsError> {
    Extensions::from_vec(vec![
        Extension::ExternalSenders(vec![server_external_sender(external_sender)]),
        Extension::RequiredCapabilities(required_capabilities()),
    ])
    .map_err(library)
}

/// What every member of a Tavern group must support: basic credentials.
/// RFC 9420 forbids listing the default extensions (external senders,
/// ratchet tree), and the ciphersuite is the group's own.
pub(crate) fn required_capabilities() -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(&[], &[], &[CredentialType::Basic])
}

/// The external sender entry for the instance's key.
fn server_external_sender(public_key: &[u8; crate::identity::PUBLIC_KEY_LEN]) -> ExternalSender {
    ExternalSender::new(
        public_key.to_vec().into(),
        openmls::prelude::BasicCredential::new(b"tavern external sender".to_vec()).into(),
    )
}

/// The configuration of a group this device creates.
pub(crate) fn create_config(
    external_sender: &[u8; crate::identity::PUBLIC_KEY_LEN],
) -> Result<MlsGroupCreateConfig, MlsError> {
    Ok(MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities())
        .padding_size(PADDING_SIZE)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(sender_ratchet())
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .with_group_context_extensions(group_context_extensions(external_sender)?)
        .build())
}

/// The configuration of a group this device joins.
pub(crate) fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .padding_size(PADDING_SIZE)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(sender_ratchet())
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

fn sender_ratchet() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAXIMUM_FORWARD_DISTANCE)
}

/// What a Tavern leaf supports: our ciphersuite, basic credentials, and the
/// last-resort KeyPackage extension (a KeyPackage may carry only extensions
/// its leaf lists).
pub(crate) fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        Some(&[ExtensionType::LastResort]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

#[cfg(test)]
mod tests;
