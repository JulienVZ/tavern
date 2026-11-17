// SPDX-License-Identifier: AGPL-3.0-or-later

//! A storage that cannot exist, for the server's MLS code.
//!
//! `ExternalProposal::new_remove` names an OpenMLS provider type only to type
//! a storage error it never produces. The only storage OpenMLS ships is the
//! in-memory one, which Tavern keeps for tests (ADR 0019; CI checks that it
//! is not linked into the server). This uninhabited type stands in: no value
//! of it can be made, so nothing is ever stored or read through it.
//!
//! Generated from `openmls_traits` 0.6.0's `StorageProvider`, without the
//! methods of features Tavern does not enable: each method body is
//! `match *self {}`. An OpenMLS upgrade that changes the trait stops this
//! file from compiling; regenerate it then.

#![allow(
    unused_variables,
    reason = "the methods of an uninhabited type never run"
)]

use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};

/// No storage at all.
#[derive(Debug)]
pub(crate) enum NoStorage {}

/// A provider type for OpenMLS functions that only name one.
#[derive(Debug)]
pub(crate) enum NoProvider {}

impl OpenMlsProvider for NoProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = NoStorage;

    fn storage(&self) -> &NoStorage {
        match *self {}
    }

    fn crypto(&self) -> &RustCrypto {
        match *self {}
    }

    fn rand(&self) -> &RustCrypto {
        match *self {}
    }
}

impl StorageProvider<CURRENT_VERSION> for NoStorage {
    type Error = std::convert::Infallible;

    fn write_mls_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn append_own_leaf_node<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        LeafNode: openmls_traits::storage::traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        match *self {}
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
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_context<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_group_state<
        GroupState: openmls_traits::storage::traits::GroupState<CURRENT_VERSION>,
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: openmls_traits::storage::traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_resumption_psk_store<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_key_package<
        HashReference: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn write_psk<
        PskId: openmls_traits::storage::traits::PskId<CURRENT_VERSION>,
        PskBundle: openmls_traits::storage::traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn mls_group_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        match *self {}
    }

    fn own_leaf_nodes<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        LeafNode: openmls_traits::storage::traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        match *self {}
    }

    fn queued_proposal_refs<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        match *self {}
    }

    fn queued_proposals<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        match *self {}
    }

    fn tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        match *self {}
    }

    fn group_context<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        match *self {}
    }

    fn interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        match *self {}
    }

    fn confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        match *self {}
    }

    fn group_state<
        GroupState: openmls_traits::storage::traits::GroupState<CURRENT_VERSION>,
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        match *self {}
    }

    fn message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: openmls_traits::storage::traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        match *self {}
    }

    fn resumption_psk_store<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        match *self {}
    }

    fn own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        match *self {}
    }

    fn group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        match *self {}
    }

    fn signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        match *self {}
    }

    fn encryption_key_pair<
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        match *self {}
    }

    fn encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        match *self {}
    }

    fn key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        match *self {}
    }

    fn psk<
        PskBundle: openmls_traits::storage::traits::PskBundle<CURRENT_VERSION>,
        PskId: openmls_traits::storage::traits::PskId<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        match *self {}
    }

    fn remove_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_own_leaf_nodes<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_group_config<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_tree<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_group_state<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_context<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_all_resumption_psk_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_own_leaf_index<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn clear_proposal_queue<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    fn delete_psk<PskKey: openmls_traits::storage::traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        match *self {}
    }
}
