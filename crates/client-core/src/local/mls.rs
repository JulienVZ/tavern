// SPDX-License-Identifier: AGPL-3.0-or-later

//! The MLS state of this device in the local store (ADR 0019, section 13):
//! OpenMLS's [`StorageProvider`] over one SQLite transaction.
//!
//! Every value OpenMLS stores is a row of `mls_state (label, key, value)`,
//! encoded as OpenMLS serialises it (serde JSON, as its own memory storage
//! does). The provider works on the transaction of the operation, so that
//! processing a message and writing its plaintext, or merging a commit and
//! recording its sequence number, commit or fail together.
//!
//! What OpenMLS deletes is deleted, never marked: the epoch secrets of a
//! past epoch, the keys of a message once decrypted, the private parts of a
//! KeyPackage once used. With `secure_delete` (set by the store), SQLite
//! overwrites what it frees with zeros; [`super::LocalStore::erase_journal`]
//! then empties the write-ahead log, which still holds the earlier pages.

use openmls_traits::storage::{CURRENT_VERSION, Key, StorageProvider, traits};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

/// The labels of the rows, one per kind of value. Never renamed: they are
/// stored.
mod label {
    pub const JOIN_CONFIG: &str = "MlsGroupJoinConfig";
    pub const OWN_LEAF_NODES: &str = "OwnLeafNodes";
    pub const QUEUED_PROPOSAL: &str = "QueuedProposal";
    pub const PROPOSAL_QUEUE_REFS: &str = "ProposalQueueRefs";
    pub const TREE: &str = "Tree";
    pub const INTERIM_TRANSCRIPT_HASH: &str = "InterimTranscriptHash";
    pub const GROUP_CONTEXT: &str = "GroupContext";
    pub const CONFIRMATION_TAG: &str = "ConfirmationTag";
    pub const GROUP_STATE: &str = "GroupState";
    pub const MESSAGE_SECRETS: &str = "MessageSecrets";
    pub const RESUMPTION_PSK_STORE: &str = "ResumptionPsk";
    pub const OWN_LEAF_NODE_INDEX: &str = "OwnLeafNodeIndex";
    pub const EPOCH_SECRETS: &str = "EpochSecrets";
    pub const SIGNATURE_KEY_PAIR: &str = "SignatureKeyPair";
    pub const ENCRYPTION_KEY_PAIR: &str = "EncryptionKeyPair";
    pub const EPOCH_KEY_PAIRS: &str = "EpochKeyPairs";
    pub const KEY_PACKAGE: &str = "KeyPackage";
    pub const PSK: &str = "Psk";
}

/// The MLS state could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum SqlStorageError {
    /// SQLite failed. Holds the error code only.
    #[error("the local store failed ({0})")]
    Database(String),
    /// A stored value does not decode, or a value does not encode.
    #[error("a value of the MLS state cannot be encoded or decoded")]
    Encoding,
}

impl From<rusqlite::Error> for SqlStorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(
            error
                .sqlite_error_code()
                .map_or_else(|| "rusqlite".to_owned(), |code| format!("{code:?}")),
        )
    }
}

impl From<serde_json::Error> for SqlStorageError {
    fn from(_: serde_json::Error) -> Self {
        Self::Encoding
    }
}

type Result<T> = std::result::Result<T, SqlStorageError>;

/// OpenMLS's storage over a connection, inside the transaction of the
/// operation: nothing is committed by the storage itself.
#[derive(Debug, Clone, Copy)]
pub struct SqlStorage<'c> {
    connection: &'c Connection,
}

impl<'c> SqlStorage<'c> {
    /// The storage over `connection`, which should be in a transaction.
    pub fn new(connection: &'c Connection) -> Self {
        Self { connection }
    }

    fn put(&self, label: &str, key: &[u8], value: &impl Serialize) -> Result<()> {
        let value = serde_json::to_vec(value)?;
        self.connection
            .prepare(
                "INSERT INTO mls_state (label, key, value) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (label, key) DO UPDATE SET value = excluded.value",
            )?
            .execute(params![label, key, value])?;
        Ok(())
    }

    fn get<V: serde::de::DeserializeOwned>(&self, label: &str, key: &[u8]) -> Result<Option<V>> {
        let value: Option<Vec<u8>> = self
            .connection
            .prepare("SELECT value FROM mls_state WHERE label = ?1 AND key = ?2")?
            .query_row(params![label, key], |row| row.get(0))
            .optional()?;
        value
            .map(|value: Vec<u8>| serde_json::from_slice(&value).map_err(SqlStorageError::from))
            .transpose()
    }

    fn remove(&self, label: &str, key: &[u8]) -> Result<()> {
        self.connection
            .prepare("DELETE FROM mls_state WHERE label = ?1 AND key = ?2")?
            .execute(params![label, key])?;
        Ok(())
    }

    /// A list stored in one row: each item encoded on its own.
    fn items(&self, label: &str, key: &[u8]) -> Result<Vec<Vec<u8>>> {
        Ok(self.get(label, key)?.unwrap_or_default())
    }

    fn push(&self, label: &str, key: &[u8], item: &impl Serialize) -> Result<()> {
        let mut items = self.items(label, key)?;
        items.push(serde_json::to_vec(item)?);
        self.put(label, key, &items)
    }

    fn pull(&self, label: &str, key: &[u8], item: &impl Serialize) -> Result<()> {
        let mut items = self.items(label, key)?;
        let item = serde_json::to_vec(item)?;
        if let Some(position) = items.iter().position(|stored| *stored == item) {
            items.remove(position);
        }
        if items.is_empty() {
            self.remove(label, key)
        } else {
            self.put(label, key, &items)
        }
    }

    fn list<V: serde::de::DeserializeOwned>(&self, label: &str, key: &[u8]) -> Result<Vec<V>> {
        self.items(label, key)?
            .iter()
            .map(|item| serde_json::from_slice(item).map_err(SqlStorageError::from))
            .collect()
    }
}

fn key(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

/// The key of a value of one group.
fn of<GroupId: Key<CURRENT_VERSION>>(group_id: &GroupId) -> Result<Vec<u8>> {
    key(group_id)
}

impl StorageProvider<CURRENT_VERSION> for SqlStorage<'_> {
    type Error = SqlStorageError;

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<()> {
        self.put(label::JOIN_CONFIG, &of(group_id)?, config)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<()> {
        self.push(label::OWN_LEAF_NODES, &of(group_id)?, leaf_node)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<()> {
        self.put(
            label::QUEUED_PROPOSAL,
            &key(&(group_id, proposal_ref))?,
            proposal,
        )?;
        self.push(label::PROPOSAL_QUEUE_REFS, &of(group_id)?, proposal_ref)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<()> {
        self.put(label::TREE, &of(group_id)?, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<()> {
        self.put(
            label::INTERIM_TRANSCRIPT_HASH,
            &of(group_id)?,
            interim_transcript_hash,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<()> {
        self.put(label::GROUP_CONTEXT, &of(group_id)?, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<()> {
        self.put(label::CONFIRMATION_TAG, &of(group_id)?, confirmation_tag)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<()> {
        self.put(label::GROUP_STATE, &of(group_id)?, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<()> {
        self.put(label::MESSAGE_SECRETS, &of(group_id)?, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<()> {
        self.put(
            label::RESUMPTION_PSK_STORE,
            &of(group_id)?,
            resumption_psk_store,
        )
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<()> {
        self.put(label::OWN_LEAF_NODE_INDEX, &of(group_id)?, own_leaf_index)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<()> {
        self.put(label::EPOCH_SECRETS, &of(group_id)?, group_epoch_secrets)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<()> {
        self.put(
            label::SIGNATURE_KEY_PAIR,
            &key(public_key)?,
            signature_key_pair,
        )
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<()> {
        self.put(label::ENCRYPTION_KEY_PAIR, &key(public_key)?, key_pair)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<()> {
        self.put(
            label::EPOCH_KEY_PAIRS,
            &key(&(group_id, epoch, leaf_index))?,
            &key_pairs,
        )
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<()> {
        self.put(label::KEY_PACKAGE, &key(hash_ref)?, key_package)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<()> {
        self.put(label::PSK, &key(psk_id)?, psk)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>> {
        self.get(label::JOIN_CONFIG, &of(group_id)?)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>> {
        self.list(label::OWN_LEAF_NODES, &of(group_id)?)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>> {
        self.list(label::PROPOSAL_QUEUE_REFS, &of(group_id)?)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>> {
        let refs: Vec<ProposalRef> = self.list(label::PROPOSAL_QUEUE_REFS, &of(group_id)?)?;
        refs.into_iter()
            .map(|proposal_ref| {
                let proposal = self
                    .get(label::QUEUED_PROPOSAL, &key(&(group_id, &proposal_ref))?)?
                    .ok_or(SqlStorageError::Encoding)?;
                Ok((proposal_ref, proposal))
            })
            .collect()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>> {
        self.get(label::TREE, &of(group_id)?)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>> {
        self.get(label::GROUP_CONTEXT, &of(group_id)?)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>> {
        self.get(label::INTERIM_TRANSCRIPT_HASH, &of(group_id)?)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>> {
        self.get(label::CONFIRMATION_TAG, &of(group_id)?)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>> {
        self.get(label::GROUP_STATE, &of(group_id)?)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>> {
        self.get(label::MESSAGE_SECRETS, &of(group_id)?)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>> {
        self.get(label::RESUMPTION_PSK_STORE, &of(group_id)?)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>> {
        self.get(label::OWN_LEAF_NODE_INDEX, &of(group_id)?)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>> {
        self.get(label::EPOCH_SECRETS, &of(group_id)?)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>> {
        self.get(label::SIGNATURE_KEY_PAIR, &key(public_key)?)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>> {
        self.get(label::ENCRYPTION_KEY_PAIR, &key(public_key)?)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>> {
        Ok(self
            .get(
                label::EPOCH_KEY_PAIRS,
                &key(&(group_id, epoch, leaf_index))?,
            )?
            .unwrap_or_default())
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>> {
        self.get(label::KEY_PACKAGE, &key(hash_ref)?)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>> {
        self.get(label::PSK, &key(psk_id)?)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<()> {
        self.pull(label::PROPOSAL_QUEUE_REFS, &of(group_id)?, proposal_ref)?;
        self.remove(label::QUEUED_PROPOSAL, &key(&(group_id, proposal_ref))?)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::OWN_LEAF_NODES, &of(group_id)?)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::JOIN_CONFIG, &of(group_id)?)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::TREE, &of(group_id)?)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::CONFIRMATION_TAG, &of(group_id)?)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::GROUP_STATE, &of(group_id)?)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::GROUP_CONTEXT, &of(group_id)?)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::INTERIM_TRANSCRIPT_HASH, &of(group_id)?)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::MESSAGE_SECRETS, &of(group_id)?)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::RESUMPTION_PSK_STORE, &of(group_id)?)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::OWN_LEAF_NODE_INDEX, &of(group_id)?)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        self.remove(label::EPOCH_SECRETS, &of(group_id)?)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<()> {
        let refs: Vec<ProposalRef> = self.list(label::PROPOSAL_QUEUE_REFS, &of(group_id)?)?;
        for proposal_ref in refs {
            self.remove(label::QUEUED_PROPOSAL, &key(&(group_id, proposal_ref))?)?;
        }
        self.remove(label::PROPOSAL_QUEUE_REFS, &of(group_id)?)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<()> {
        self.remove(label::SIGNATURE_KEY_PAIR, &key(public_key)?)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<()> {
        self.remove(label::ENCRYPTION_KEY_PAIR, &key(public_key)?)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<()> {
        self.remove(
            label::EPOCH_KEY_PAIRS,
            &key(&(group_id, epoch, leaf_index))?,
        )
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<()> {
        self.remove(label::KEY_PACKAGE, &key(hash_ref)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(&self, psk_id: &PskKey) -> Result<()> {
        self.remove(label::PSK, &key(psk_id)?)
    }
}
