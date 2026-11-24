// SPDX-License-Identifier: AGPL-3.0-or-later

//! The server's view of a group (ADR 0019, sections 4 to 7 and 14).
//!
//! OpenMLS keeps a group's public state without any secret: the ratchet
//! tree, the group context, the confirmation tag and the interim transcript
//! hash, and the stored proposals. The server builds it from the GroupInfo
//! submitted with a group's first commit, checks every later commit against
//! it with the same policy as the clients, merges it once accepted, and
//! signs its own `Remove` proposals. Nothing here decrypts anything.
//!
//! The state is made of rows ([`PublicEntries`]): the server loads a group's
//! rows at the start of a request and writes back those that changed in the
//! transaction that moves the epoch.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::{DeserializeBytes, Serialize as _};
use openmls::prelude::{
    ContentType, ExternalProposal, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    OpenMlsSignaturePublicKey, ProcessedMessageContent, ProposalStore, ProtocolMessage,
    PublicGroup, PublicProcessMessageError, Sender, SenderExtensionIndex, StagedCommit, Verifiable,
};
use openmls::treesync::EncryptionKey;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::public_storage::PublicStorageProvider;
use openmls_traits::storage::CURRENT_VERSION;
use openmls_traits::types::SignatureScheme;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::credential::{LeafError, Roster, VerifiedLeaf, name_leaf, verify_members};
use super::group::{ExpectedGroup, check_context};
use super::group_id::GroupIdentity;
use super::no_storage::NoProvider;
use super::policy::{self, Alarm, GroupView};
use super::{MembershipChanges, MlsError, Refusal, ServerSigner, library};
use crate::identity::PUBLIC_KEY_LEN;

/// The kind of the row that lists a group's queued proposals, present only
/// while some are queued. The server queues its own `Remove` proposals only
/// (section 6): a group with such a row has removals pending, and its
/// members may send no application message (`REMOVAL_PENDING`).
pub const PROPOSAL_QUEUE_KIND: i16 = 5;

/// What the server reads of an application message before it sequences it:
/// its group and its epoch, which a `PrivateMessage` carries in clear (RFC
/// 9420, section 6.3). Nothing else is readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationHeader {
    /// The group: conversation and generation.
    pub group: GroupIdentity,
    /// The epoch it is encrypted for.
    pub epoch: u64,
}

/// Reads the header of an application message: an MLS `PrivateMessage`
/// carrying application content, and nothing after it. Anything else is
/// refused: commits and proposals travel as `PublicMessage`s, and
/// application content never does.
pub fn application_header(bytes: &[u8]) -> Result<ApplicationHeader, MlsError> {
    let (message, rest) =
        MlsMessageIn::tls_deserialize_bytes(bytes).map_err(|_| MlsError::Malformed)?;
    if !rest.is_empty() {
        return Err(MlsError::Malformed);
    }
    let MlsMessageBodyIn::PrivateMessage(message) = message.extract() else {
        return Err(MlsError::Malformed);
    };
    if message.content_type() != ContentType::Application {
        return Err(MlsError::Malformed);
    }
    Ok(ApplicationHeader {
        group: GroupIdentity::from_group_id(message.group_id())?,
        epoch: message.epoch().as_u64(),
    })
}

/// Checks the framing of a group's first commit, which the server cannot
/// check otherwise (it has no state of epoch 0, section 4): a
/// `PublicMessage` carrying a commit, for `identity`'s group at epoch 0,
/// from a member. Returns the committer's leaf index.
pub fn first_commit_sender(bytes: &[u8], identity: GroupIdentity) -> Result<u32, MlsError> {
    let (message, rest) =
        MlsMessageIn::tls_deserialize_bytes(bytes).map_err(|_| MlsError::Malformed)?;
    if !rest.is_empty() {
        return Err(MlsError::Malformed);
    }
    let MlsMessageBodyIn::PublicMessage(message) = message.extract() else {
        return Err(MlsError::Malformed);
    };
    if message.content_type() != ContentType::Commit
        || *message.group_id() != identity.to_group_id()
        || message.epoch().as_u64() != 0
    {
        return Err(MlsError::Malformed);
    }
    match message.sender() {
        Sender::Member(index) => Ok(index.u32()),
        _ => Err(MlsError::Malformed),
    }
}

/// Whether a commit's framing says it is an external commit (sender
/// `NewMemberCommit`), read before it is checked: what a device the server
/// is removing may still submit (sections 6 and 15). `false` for anything
/// that is not a `PublicMessage` carrying a commit.
pub fn is_external_commit(bytes: &[u8]) -> bool {
    let Ok((message, _)) = MlsMessageIn::tls_deserialize_bytes(bytes) else {
        return false;
    };
    let MlsMessageBodyIn::PublicMessage(message) = message.extract() else {
        return false;
    };
    message.content_type() == ContentType::Commit
        && matches!(message.sender(), Sender::NewMemberCommit)
}

/// The KeyPackages a Welcome is for (their `KeyPackageRef`s, in clear in
/// it), in order. Refused unless it is a Welcome of Tavern's ciphersuite,
/// with nothing after it.
pub fn welcome_key_packages(bytes: &[u8]) -> Result<Vec<Vec<u8>>, MlsError> {
    let (message, rest) =
        MlsMessageIn::tls_deserialize_bytes(bytes).map_err(|_| MlsError::Malformed)?;
    if !rest.is_empty() {
        return Err(MlsError::Malformed);
    }
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(MlsError::Malformed);
    };
    if welcome.ciphersuite() != super::CIPHERSUITE {
        return Err(MlsError::Parameters);
    }
    Ok(welcome
        .secrets()
        .iter()
        .map(|secret| secret.new_member().as_slice().to_vec())
        .collect())
}

/// What a row holds. The numbers are stored: never change or reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Tree,
    Context,
    InterimTranscriptHash,
    ConfirmationTag,
    /// The references of the stored proposals, in order.
    ProposalQueue,
    /// One stored proposal, keyed by its reference.
    Proposal,
}

impl Kind {
    const ALL: [Self; 6] = [
        Self::Tree,
        Self::Context,
        Self::InterimTranscriptHash,
        Self::ConfirmationTag,
        Self::ProposalQueue,
        Self::Proposal,
    ];

    fn code(self) -> i16 {
        match self {
            Self::Tree => 1,
            Self::Context => 2,
            Self::InterimTranscriptHash => 3,
            Self::ConfirmationTag => 4,
            Self::ProposalQueue => 5,
            Self::Proposal => 6,
        }
    }

    fn from_code(code: i16) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.code() == code)
    }
}

/// One row of a group's public state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// What the row holds: a small number, stable across releases.
    pub kind: i16,
    /// Within its kind: empty, or a proposal's reference.
    pub key: Vec<u8>,
    /// The value, as OpenMLS serialises it (JSON).
    pub value: Vec<u8>,
}

/// A row to write back after an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Insert the row, or replace it.
    Write(Entry),
    /// Delete the row.
    Delete {
        /// Its kind.
        kind: i16,
        /// Its key.
        key: Vec<u8>,
    },
}

/// Why OpenMLS could not read or write a row.
#[derive(Debug, thiserror::Error)]
pub enum EntriesError {
    /// The row belongs to another group than these entries'.
    #[error("an entry of another group")]
    OtherGroup,
    /// A value could not be encoded or decoded.
    #[error("an entry cannot be encoded or decoded: {0}")]
    Encoding(String),
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, EntriesError> {
    serde_json::to_vec(value).map_err(|error| EntriesError::Encoding(error.to_string()))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, EntriesError> {
    serde_json::from_slice(bytes).map_err(|error| EntriesError::Encoding(error.to_string()))
}

/// A row's place: its kind and its key.
type Place = (Kind, Vec<u8>);

/// The rows of one group's public state, read and written by OpenMLS
/// through [`PublicStorageProvider`]. They remember which rows changed, for
/// the server to write back ([`PublicEntries::take_changes`]).
#[derive(Debug)]
pub struct PublicEntries {
    /// The group id, as OpenMLS serialises it as a key.
    group_key: Vec<u8>,
    rows: RefCell<BTreeMap<Place, Vec<u8>>>,
    changed: RefCell<BTreeSet<Place>>,
}

impl PublicEntries {
    /// No rows yet: a group about to be created.
    pub fn new(identity: GroupIdentity) -> Result<Self, MlsError> {
        Ok(Self {
            group_key: encode(&identity.to_group_id()).map_err(library)?,
            rows: RefCell::default(),
            changed: RefCell::default(),
        })
    }

    /// The rows of a group, as the server stored them.
    pub fn load(
        identity: GroupIdentity,
        entries: impl IntoIterator<Item = Entry>,
    ) -> Result<Self, MlsError> {
        let loaded = Self::new(identity)?;
        {
            let mut rows = loaded.rows.borrow_mut();
            for entry in entries {
                let kind = Kind::from_code(entry.kind).ok_or(MlsError::Malformed)?;
                rows.insert((kind, entry.key), entry.value);
            }
        }
        Ok(loaded)
    }

    /// Every row: for a group the server stores for the first time.
    pub fn entries(&self) -> Vec<Entry> {
        self.rows
            .borrow()
            .iter()
            .map(|((kind, key), value)| Entry {
                kind: kind.code(),
                key: key.clone(),
                value: value.clone(),
            })
            .collect()
    }

    /// The rows written or deleted since the last call, to write back.
    pub fn take_changes(&self) -> Vec<Change> {
        let rows = self.rows.borrow();
        std::mem::take(&mut *self.changed.borrow_mut())
            .into_iter()
            .map(|(kind, key)| match rows.get(&(kind, key.clone())) {
                Some(value) => Change::Write(Entry {
                    kind: kind.code(),
                    key,
                    value: value.clone(),
                }),
                None => Change::Delete {
                    kind: kind.code(),
                    key,
                },
            })
            .collect()
    }

    fn check<T: Serialize + ?Sized>(&self, group_id: &T) -> Result<(), EntriesError> {
        if encode(group_id)? == self.group_key {
            Ok(())
        } else {
            Err(EntriesError::OtherGroup)
        }
    }

    fn put(&self, kind: Kind, key: Vec<u8>, value: Vec<u8>) {
        self.rows.borrow_mut().insert((kind, key.clone()), value);
        self.changed.borrow_mut().insert((kind, key));
    }

    fn get<T: DeserializeOwned>(&self, kind: Kind, key: &[u8]) -> Result<Option<T>, EntriesError> {
        self.rows
            .borrow()
            .get(&(kind, key.to_vec()))
            .map(|value| decode(value))
            .transpose()
    }

    fn remove(&self, kind: Kind, key: Vec<u8>) {
        self.rows.borrow_mut().remove(&(kind, key.clone()));
        self.changed.borrow_mut().insert((kind, key));
    }

    fn queue(&self) -> Result<Vec<serde_json::Value>, EntriesError> {
        Ok(self.get(Kind::ProposalQueue, &[])?.unwrap_or_default())
    }

    fn set_queue(&self, queue: &[serde_json::Value]) -> Result<(), EntriesError> {
        if queue.is_empty() {
            self.remove(Kind::ProposalQueue, Vec::new());
        } else {
            self.put(Kind::ProposalQueue, Vec::new(), encode(queue)?);
        }
        Ok(())
    }
}

impl PublicStorageProvider<CURRENT_VERSION> for PublicEntries {
    type PublicError = EntriesError;

    fn write_tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        self.put(Kind::Tree, Vec::new(), encode(tree)?);
        Ok(())
    }

    fn write_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        self.put(
            Kind::InterimTranscriptHash,
            Vec::new(),
            encode(interim_transcript_hash)?,
        );
        Ok(())
    }

    fn write_context<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        self.put(Kind::Context, Vec::new(), encode(group_context)?);
        Ok(())
    }

    fn write_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        self.put(Kind::ConfirmationTag, Vec::new(), encode(confirmation_tag)?);
        Ok(())
    }

    fn queue_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        let reference = serde_json::to_value(proposal_ref)
            .map_err(|error| EntriesError::Encoding(error.to_string()))?;
        self.put(Kind::Proposal, encode(proposal_ref)?, encode(proposal)?);
        let mut queue = self.queue()?;
        if !queue.contains(&reference) {
            queue.push(reference);
            self.set_queue(&queue)?;
        }
        Ok(())
    }

    fn queued_proposals<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, EntriesError> {
        self.check(group_id)?;
        let references: Vec<ProposalRef> = self.get(Kind::ProposalQueue, &[])?.unwrap_or_default();
        references
            .into_iter()
            .map(|reference| {
                let proposal = self
                    .get(Kind::Proposal, &encode(&reference)?)?
                    .ok_or_else(|| EntriesError::Encoding("a queued proposal is missing".into()))?;
                Ok((reference, proposal))
            })
            .collect()
    }

    fn tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, EntriesError> {
        self.check(group_id)?;
        self.get(Kind::Tree, &[])
    }

    fn group_context<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, EntriesError> {
        self.check(group_id)?;
        self.get(Kind::Context, &[])
    }

    fn interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, EntriesError> {
        self.check(group_id)?;
        self.get(Kind::InterimTranscriptHash, &[])
    }

    fn confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, EntriesError> {
        self.check(group_id)?;
        self.get(Kind::ConfirmationTag, &[])
    }

    fn delete_tree<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        self.remove(Kind::Tree, Vec::new());
        Ok(())
    }

    fn delete_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        self.remove(Kind::ConfirmationTag, Vec::new());
        Ok(())
    }

    fn delete_context<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        self.remove(Kind::Context, Vec::new());
        Ok(())
    }

    fn delete_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        self.remove(Kind::InterimTranscriptHash, Vec::new());
        Ok(())
    }

    fn remove_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        let reference = serde_json::to_value(proposal_ref)
            .map_err(|error| EntriesError::Encoding(error.to_string()))?;
        let mut queue = self.queue()?;
        queue.retain(|queued| *queued != reference);
        self.set_queue(&queue)?;
        self.remove(Kind::Proposal, encode(proposal_ref)?);
        Ok(())
    }

    fn clear_proposal_queue<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), EntriesError> {
        self.check(group_id)?;
        let stored: Vec<Vec<u8>> = self
            .rows
            .borrow()
            .keys()
            .filter(|(kind, _)| *kind == Kind::Proposal)
            .map(|(_, key)| key.clone())
            .collect();
        for key in stored {
            self.remove(Kind::Proposal, key);
        }
        self.remove(Kind::ProposalQueue, Vec::new());
        Ok(())
    }
}

/// The policy's view of a public group, with its stored proposals.
struct PublicView<'a> {
    group: &'a PublicGroup,
    requested: HashSet<LeafNodeIndex>,
}

impl GroupView for PublicView<'_> {
    fn device_at(&self, index: LeafNodeIndex) -> Option<VerifiedLeaf> {
        self.group
            .leaf(index)
            .and_then(|leaf| name_leaf(leaf.credential()))
    }

    fn leaves(&self) -> Vec<(LeafNodeIndex, VerifiedLeaf)> {
        policy::named_leaves(self.group.members())
    }

    fn signature_key(&self, index: LeafNodeIndex) -> Option<Vec<u8>> {
        self.group
            .leaf(index)
            .map(|leaf| leaf.signature_key().as_slice().to_vec())
    }

    fn credential(&self, index: LeafNodeIndex) -> Option<openmls::prelude::Credential> {
        self.group.leaf(index).map(|leaf| leaf.credential().clone())
    }

    fn requested_removals(&self) -> HashSet<LeafNodeIndex> {
        self.requested.clone()
    }
}

/// A commit the server accepts, once checked: merged with
/// [`PublicState::merge`] in the transaction that moves the epoch.
#[derive(Debug)]
pub struct ValidatedCommit {
    staged: StagedCommit,
    external: bool,
    changes: MembershipChanges,
    removed: HashSet<LeafNodeIndex>,
    group_info: Vec<u8>,
    added_key_packages: Vec<Vec<u8>>,
}

impl ValidatedCommit {
    /// Who joins and who leaves.
    pub fn changes(&self) -> &MembershipChanges {
        &self.changes
    }

    /// The epoch the commit starts.
    pub fn epoch(&self) -> u64 {
        self.staged.epoch().as_u64()
    }

    /// Whether it is an external commit: a device joining, or coming back.
    pub fn is_external(&self) -> bool {
        self.external
    }

    /// The `KeyPackageRef`s of the KeyPackages the commit adds: the ones
    /// its Welcome must be for, exactly.
    pub fn added_key_packages(&self) -> &[Vec<u8>] {
        &self.added_key_packages
    }
}

/// A commit merged into the public state.
#[derive(Debug)]
pub struct MergedCommit {
    /// Who joined and who left.
    pub changes: MembershipChanges,
    /// The new epoch.
    pub epoch: u64,
    /// The server's removals that the commit did not carry (an external
    /// commit cannot), signed again for the new epoch: to append to the
    /// conversation's sequence right after the commit (sections 5 and 6).
    /// In the order of their leaves.
    pub reissued: Vec<Reissued>,
}

/// A removal the server asked again for, in a new epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reissued {
    /// The leaf to remove: a leaf index does not move in MLS, so it is the
    /// one first asked for.
    pub leaf: u32,
    /// The signed `Remove` proposal (`PublicMessage`).
    pub proposal: Vec<u8>,
}

/// The public state of one group, on the server, with the latest GroupInfo
/// it checked.
pub struct PublicState {
    group: PublicGroup,
    entries: PublicEntries,
    group_info: Vec<u8>,
    crypto: RustCrypto,
}

impl std::fmt::Debug for PublicState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicState")
            .field("epoch", &self.epoch())
            .field("devices", &self.devices().len())
            .finish_non_exhaustive()
    }
}

fn parse_group_info(bytes: &[u8]) -> Result<VerifiableGroupInfo, MlsError> {
    let (message, rest) =
        MlsMessageIn::tls_deserialize_bytes(bytes).map_err(|_| MlsError::Malformed)?;
    if !rest.is_empty() {
        return Err(MlsError::Malformed);
    }
    match message.extract() {
        MlsMessageBodyIn::GroupInfo(info) => Ok(info),
        _ => Err(MlsError::Malformed),
    }
}

/// A public group from a GroupInfo and its ratchet tree. OpenMLS checks the
/// GroupInfo's signature by its signer's leaf, the tree against the group
/// context's tree hash, and every leaf.
fn group_from_info(
    crypto: &RustCrypto,
    entries: &PublicEntries,
    info: VerifiableGroupInfo,
) -> Result<PublicGroup, String> {
    let tree = info
        .extensions()
        .ratchet_tree()
        .ok_or_else(|| "the GroupInfo has no ratchet tree".to_owned())?
        .ratchet_tree()
        .clone();
    PublicGroup::from_external(crypto, entries, tree, info, ProposalStore::new())
        .map(|(group, _)| group)
        .map_err(|error| error.to_string())
}

/// Checks a GroupInfo to keep for devices that join by external commit: its
/// ratchet tree matches its group context (OpenMLS builds a public group
/// from it, checking the tree hash, every leaf and the signature by its
/// signer), it carries the `ExternalPub` they need, and it is signed by
/// `signer`'s leaf. Returns the public group it describes.
fn check_group_info(
    crypto: &RustCrypto,
    bytes: &[u8],
    identity: GroupIdentity,
    signer: VerifiedLeaf,
) -> Result<PublicGroup, MlsError> {
    let info = parse_group_info(bytes)?;
    if info.extensions().external_pub().is_none() {
        return Err(MlsError::GroupInfo);
    }
    let scratch = PublicEntries::new(identity)?;
    let group = group_from_info(crypto, &scratch, info).map_err(|_| MlsError::GroupInfo)?;
    if !signed_by(crypto, &group, parse_group_info(bytes)?, signer) {
        return Err(MlsError::GroupInfo);
    }
    Ok(group)
}

/// Whether `info` is signed by `device`'s leaf in `group`.
fn signed_by(
    crypto: &RustCrypto,
    group: &PublicGroup,
    info: VerifiableGroupInfo,
    device: VerifiedLeaf,
) -> bool {
    let Some(key) = group
        .members()
        .find(|member| name_leaf(&member.credential) == Some(device))
        .map(|member| member.signature_key)
    else {
        return false;
    };
    OpenMlsSignaturePublicKey::new(key.into(), SignatureScheme::ED25519)
        .is_ok_and(|key| info.verify(crypto, &key).is_ok())
}

/// A commit the server refuses, as one of the client's alarms would say.
fn refused(alarm: Alarm) -> MlsError {
    match alarm {
        Alarm::Leaf(error) => MlsError::Leaf(error),
        Alarm::Policy(error) => MlsError::Policy(error),
        Alarm::UnknownProposal => MlsError::Invalid(alarm.to_string()),
        Alarm::InvalidCommit(text) => MlsError::Invalid(text),
    }
}

fn public_error(error: PublicProcessMessageError) -> MlsError {
    match error {
        PublicProcessMessageError::LibraryError(error) => library(error),
        other => MlsError::Invalid(other.to_string()),
    }
}

fn to_bytes(message: &MlsMessageOut) -> Result<Vec<u8>, MlsError> {
    message.tls_serialize_detached().map_err(library)
}

impl PublicState {
    /// Builds the state from the GroupInfo submitted with a group's first
    /// commit (epoch 1): the server has no state of epoch 0 to check that
    /// commit against (section 4). The group must be the expected one with
    /// Tavern's parameters; every leaf an active, certified device of a
    /// participant (a participant may have none); the GroupInfo signed by
    /// the submitting device, which is in the group, and carrying the
    /// `ExternalPub` that devices joining by external commit need. Returns
    /// the state, which keeps that GroupInfo, and its devices.
    pub fn create(
        group_info: &[u8],
        expected: &ExpectedGroup<'_>,
        submitter: VerifiedLeaf,
        roster: &impl Roster,
        external_sender: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(Self, Vec<VerifiedLeaf>), MlsError> {
        let crypto = RustCrypto::default();
        let info = parse_group_info(group_info)?;
        let context = info.group_context();
        check_context(
            context.ciphersuite(),
            context.group_id(),
            context.extensions(),
            expected,
            external_sender,
        )?;
        if info.epoch().as_u64() != 1 {
            return Err(MlsError::UnexpectedGroup);
        }
        let entries = PublicEntries::new(expected.identity)?;
        let group = group_from_info(&crypto, &entries, info).map_err(MlsError::Invalid)?;
        let members: Vec<_> = group.members().collect();
        let devices = verify_members(
            members
                .iter()
                .map(|member| (&member.credential, member.signature_key.as_slice())),
            roster,
        )?;
        expected.check_members(&devices)?;
        if !signed_by(&crypto, &group, parse_group_info(group_info)?, submitter) {
            return Err(MlsError::WrongSender);
        }
        check_group_info(&crypto, group_info, expected.identity, submitter)?;
        // `from_external` wrote the state into the entries: they are to be
        // stored whole ([`PublicEntries::entries`]), not as changes.
        entries.take_changes();
        Ok((
            Self {
                group,
                entries,
                group_info: group_info.to_vec(),
                crypto,
            },
            devices,
        ))
    }

    /// The state the server stored for `identity`, with the GroupInfo it
    /// stored with it.
    pub fn load(
        identity: GroupIdentity,
        entries: PublicEntries,
        group_info: Vec<u8>,
    ) -> Result<Self, MlsError> {
        let group = PublicGroup::load(&entries, &identity.to_group_id())
            .map_err(|error| match error {
                EntriesError::OtherGroup => MlsError::UnexpectedGroup,
                EntriesError::Encoding(_) => MlsError::Malformed,
            })?
            .ok_or(MlsError::Malformed)?;
        Ok(Self {
            group,
            entries,
            group_info,
            crypto: RustCrypto::default(),
        })
    }

    /// The rows, to store or to write back.
    pub fn entries(&self) -> &PublicEntries {
        &self.entries
    }

    /// The latest GroupInfo, checked: the one to keep for devices that join
    /// by external commit.
    pub fn group_info(&self) -> &[u8] {
        &self.group_info
    }

    /// Which conversation and generation.
    pub fn identity(&self) -> Result<GroupIdentity, MlsError> {
        GroupIdentity::from_group_id(self.group.group_id())
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }

    /// The devices in the group.
    pub fn devices(&self) -> Vec<VerifiedLeaf> {
        policy::named_leaves(self.group.members())
            .into_iter()
            .map(|(_, leaf)| leaf)
            .collect()
    }

    /// The devices in the group, each with the index of its leaf.
    pub fn leaves(&self) -> Vec<(u32, VerifiedLeaf)> {
        policy::named_leaves(self.group.members())
            .into_iter()
            .map(|(index, leaf)| (index.u32(), leaf))
            .collect()
    }

    /// The devices in the group, each with the encryption key of its leaf:
    /// for a device a commit just added, the key of the KeyPackage that
    /// added it ([`UploadedKeyPackage::leaf_key`](super::key_package::UploadedKeyPackage)).
    pub fn leaf_keys(&self) -> Vec<(VerifiedLeaf, Vec<u8>)> {
        self.group
            .members()
            .filter_map(|member| {
                let leaf = policy::member_leaf(&member)?;
                let key = EncryptionKey::from(member.encryption_key)
                    .tls_serialize_detached()
                    .ok()?;
                Some((leaf, key))
            })
            .collect()
    }

    /// The leaf of a device, if it is in the group.
    pub fn leaf_of(&self, device: VerifiedLeaf) -> Option<LeafNodeIndex> {
        policy::named_leaves(self.group.members())
            .into_iter()
            .find_map(|(index, leaf)| (leaf == device).then_some(index))
    }

    fn view(&self) -> Result<PublicView<'_>, MlsError> {
        let queued = self
            .group
            .queued_proposals(&self.entries)
            .map_err(library)?;
        Ok(PublicView {
            group: &self.group,
            requested: policy::requested_by_server(queued.iter().map(|(_, proposal)| proposal)),
        })
    }

    /// The leaves the server has asked to remove, not committed yet.
    pub fn pending_removals(&self) -> Result<Vec<LeafNodeIndex>, MlsError> {
        let mut pending: Vec<_> = self.view()?.requested.into_iter().collect();
        pending.sort_by_key(LeafNodeIndex::u32);
        Ok(pending)
    }

    /// Checks a commit submitted by `submitter` for the current epoch, with
    /// the GroupInfo of its new epoch. Refused: another epoch (`STALE_EPOCH`
    /// for a past one), a commit that is not the submitter's own, anything
    /// OpenMLS finds invalid against the public state, anything the clients'
    /// policy refuses (sections 2, 5 and 6), a device of anyone but the
    /// participants, a member's commit that leaves out a removal the server
    /// asked for (`REMOVAL_PENDING`), and a GroupInfo that is not the new
    /// epoch's (the same group context and confirmation tag as the commit's,
    /// with `ExternalPub` and the ratchet tree), signed by the committer.
    pub fn validate_commit(
        &self,
        commit: &[u8],
        group_info: &[u8],
        submitter: VerifiedLeaf,
        expected: &ExpectedGroup<'_>,
        roster: &impl Roster,
    ) -> Result<ValidatedCommit, MlsError> {
        let (message, rest) =
            MlsMessageIn::tls_deserialize_bytes(commit).map_err(|_| MlsError::Malformed)?;
        if !rest.is_empty() {
            return Err(MlsError::Malformed);
        }
        let protocol: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|_| MlsError::Malformed)?;
        let ProtocolMessage::PublicMessage(public) = &protocol else {
            return Err(MlsError::Malformed);
        };
        if protocol.content_type() != ContentType::Commit {
            return Err(MlsError::Malformed);
        }
        let confirmation_tag = public
            .confirmation_tag()
            .cloned()
            .ok_or(MlsError::Malformed)?;
        if protocol.group_id() != self.group.group_id() {
            return Err(MlsError::Refused(Refusal::WrongGroup));
        }
        let (epoch, current) = (protocol.epoch(), self.group.group_context().epoch());
        if epoch < current {
            return Err(MlsError::Refused(Refusal::PastEpoch));
        }
        if epoch > current {
            return Err(MlsError::Refused(Refusal::WrongEpoch));
        }

        let processed = self
            .group
            .process_message(&self.crypto, protocol)
            .map_err(public_error)?;
        let sender = processed.sender().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(MlsError::Malformed);
        };
        let view = self.view()?;
        // A device submits its own commits only.
        let committer = match &sender {
            Sender::Member(index) => view.device_at(*index),
            Sender::NewMemberCommit => staged
                .update_path_leaf_node()
                .and_then(|leaf| name_leaf(leaf.credential())),
            Sender::External(_) | Sender::NewMemberProposal => None,
        };
        if committer != Some(submitter) {
            return Err(MlsError::WrongSender);
        }
        let changes = policy::check_commit(&view, &staged, &sender, roster).map_err(refused)?;
        expected.check_members(&changes.added)?;

        let removed: HashSet<LeafNodeIndex> = staged
            .remove_proposals()
            .map(|remove| remove.remove_proposal().removed())
            .collect();
        let external = matches!(sender, Sender::NewMemberCommit);
        if !external && !view.requested.is_subset(&removed) {
            return Err(MlsError::RemovalPending);
        }

        if parse_group_info(group_info)?.group_context() != staged.group_context() {
            return Err(MlsError::GroupInfo);
        }
        let next = check_group_info(&self.crypto, group_info, self.identity()?, submitter)?;
        if *next.confirmation_tag() != confirmation_tag {
            return Err(MlsError::GroupInfo);
        }

        let added_key_packages = staged
            .add_proposals()
            .map(|add| {
                add.add_proposal()
                    .key_package()
                    .hash_ref(&self.crypto)
                    .map(|reference| reference.as_slice().to_vec())
                    .map_err(library)
            })
            .collect::<Result<_, _>>()?;
        Ok(ValidatedCommit {
            staged: *staged,
            external,
            changes,
            removed,
            group_info: group_info.to_vec(),
            added_key_packages,
        })
    }

    /// Merges a commit [`PublicState::validate_commit`] accepted, in the
    /// transaction that moves the epoch. The server's removals the commit
    /// did not carry are signed again for the new epoch (section 6): after a
    /// member's commit there are none (it had to carry them), after an
    /// external commit there are all but the joining device's own earlier
    /// leaf, which the commit removed (a resync).
    pub fn merge(
        &mut self,
        validated: ValidatedCommit,
        signer: &ServerSigner<'_>,
    ) -> Result<MergedCommit, MlsError> {
        let pending = self.pending_removals()?;
        self.group
            .merge_commit(&self.entries, validated.staged)
            .map_err(library)?;
        let mut reissued = Vec::new();
        for leaf in pending {
            if !validated.removed.contains(&leaf)
                && let Some(proposal) = self.remove(leaf, signer)?
            {
                reissued.push(Reissued {
                    leaf: leaf.u32(),
                    proposal,
                });
            }
        }
        self.group_info = validated.group_info;
        Ok(MergedCommit {
            changes: validated.changes,
            epoch: self.epoch(),
            reissued,
        })
    }

    /// The server's `Remove` of the leaf `leaf` for the current epoch,
    /// signed with the external sender key and stored, to deliver in the
    /// conversation's sequence (section 6). `None` if the server already
    /// asked for it in this epoch.
    pub fn remove(
        &mut self,
        leaf: LeafNodeIndex,
        signer: &ServerSigner<'_>,
    ) -> Result<Option<Vec<u8>>, MlsError> {
        if self.group.leaf(leaf).is_none() {
            return Err(MlsError::Leaf(LeafError::Malformed));
        }
        if self.view()?.requested.contains(&leaf) {
            return Ok(None);
        }
        let message = ExternalProposal::new_remove::<NoProvider>(
            leaf,
            self.group.group_id().clone(),
            self.group.group_context().epoch(),
            signer,
            SenderExtensionIndex::new(0),
        )
        .map_err(library)?;
        let bytes = to_bytes(&message)?;
        // Through OpenMLS's own checks, like any proposal, then stored.
        let (incoming, _) =
            MlsMessageIn::tls_deserialize_bytes(&bytes).map_err(|_| MlsError::Malformed)?;
        let protocol = incoming
            .try_into_protocol_message()
            .map_err(|_| MlsError::Malformed)?;
        let processed = self
            .group
            .process_message(&self.crypto, protocol)
            .map_err(public_error)?;
        let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
            return Err(MlsError::Malformed);
        };
        self.group
            .add_proposal(&self.entries, *queued)
            .map_err(library)?;
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proposal_queue_kind_is_the_stored_one() {
        assert_eq!(PROPOSAL_QUEUE_KIND, Kind::ProposalQueue.code());
    }
}
