// SPDX-License-Identifier: AGPL-3.0-or-later

//! A Tavern MLS group: one per conversation (ADR 0019, sections 4 to 9).
//!
//! Every method takes the OpenMLS provider whose storage holds the group's
//! state, so that the caller decides where and in which transaction it is
//! written (section 13). Commits created here stay pending until the server
//! accepts them ([`Group::merge_pending_commit`]) or refuses them
//! ([`Group::discard_pending_commit`]), as section 7 requires. They carry
//! only the proposals chosen here, never whatever OpenMLS has stored, and
//! pass the same checks as other devices' commits before they are returned.

use std::collections::HashSet;

use openmls::prelude::tls_codec::{DeserializeBytes, Serialize as _};
use openmls::prelude::{
    CommitMessageBundle, CredentialWithKey, KeyPackage, LeafNodeIndex, MlsGroup, MlsMessageBodyIn,
    MlsMessageIn, MlsMessageOut, ProcessedMessageContent, ProtocolMessage, ProtocolVersion, Sender,
    StagedWelcome,
};
use openmls_traits::OpenMlsProvider;

use super::credential::{LeafError, Roster, VerifiedLeaf, name_leaf, verify_leaf, verify_members};
use super::group_id::GroupIdentity;
use super::policy::{self, Alarm, PolicyError};
use super::{
    CIPHERSUITE, DeviceSigner, MlsError, create_config, join_config, library, padding,
    processing_error, server_external_sender,
};
use crate::identity::{ID_LEN, PUBLIC_KEY_LEN};

/// Who joined and who left with a commit. Both are shown in the
/// conversation (sections 5 and 6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MembershipChanges {
    /// Leaves added: new devices, or a device rejoining by external commit.
    pub added: Vec<VerifiedLeaf>,
    /// Leaves removed.
    pub removed: Vec<VerifiedLeaf>,
}

/// A commit this device created, to submit to the server.
#[derive(Debug, Clone)]
pub struct Commit {
    /// The commit (`PublicMessage`).
    pub commit: Vec<u8>,
    /// The Welcome for added devices, if any.
    pub welcome: Option<Vec<u8>>,
    /// The GroupInfo of the new epoch, with the ratchet tree, for devices
    /// that will join by external commit.
    pub group_info: Vec<u8>,
}

/// What an incoming message turned out to be, once accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// Content from a member, padding removed.
    Application {
        /// The device that sent it.
        sender: Option<VerifiedLeaf>,
        /// The content (`tavern.content.v1`).
        content: Vec<u8>,
    },
    /// One of the server's `Remove` proposals, checked and stored: a commit
    /// will refer to it.
    Proposal,
    /// A commit of another device, checked and merged: the group is in a new
    /// epoch.
    Commit {
        /// Who joined and who left.
        changes: MembershipChanges,
        /// This device was removed: it can read nothing more in the group.
        self_removed: bool,
    },
    /// This device's own pending commit, fanned out by the server: merged.
    OwnCommit,
    /// One of this device's own messages, sent back: nothing to do.
    OwnMessage,
}

/// A Tavern MLS group.
#[derive(Debug)]
pub struct Group {
    inner: MlsGroup,
}

fn to_bytes(message: &MlsMessageOut) -> Result<Vec<u8>, MlsError> {
    message.tls_serialize_detached().map_err(library)
}

fn parse(bytes: &[u8]) -> Result<MlsMessageIn, MlsError> {
    let (message, rest) =
        MlsMessageIn::tls_deserialize_bytes(bytes).map_err(|_| MlsError::Malformed)?;
    if !rest.is_empty() {
        return Err(MlsError::Malformed);
    }
    Ok(message)
}

fn commit_from_bundle(bundle: CommitMessageBundle) -> Result<Commit, MlsError> {
    let (commit, welcome, group_info) = bundle.into_contents();
    Ok(Commit {
        commit: to_bytes(&commit)?,
        welcome: welcome
            .map(|welcome| {
                to_bytes(&MlsMessageOut::from_welcome(
                    welcome,
                    ProtocolVersion::Mls10,
                ))
            })
            .transpose()?,
        group_info: group_info
            .ok_or(MlsError::Malformed)
            .and_then(|info| to_bytes(&MlsMessageOut::from(info)))?,
    })
}

/// An own commit that fails the checks is a bug of this device, not an
/// alarm about others.
fn own_commit_error(alarm: Alarm) -> MlsError {
    match alarm {
        Alarm::Leaf(error) => MlsError::Leaf(error),
        Alarm::Policy(error) => MlsError::Policy(error),
        Alarm::UnknownProposal => MlsError::Malformed,
    }
}

impl Group {
    /// Creates the group of a conversation and adds `key_packages` (the
    /// other devices of this user and the peer's devices) in one commit,
    /// which stays pending. Each package must pass the roster: the server
    /// hands them out, and could slip in a device of its own.
    pub fn create<P: OpenMlsProvider>(
        provider: &P,
        signer: &DeviceSigner<'_>,
        credential: CredentialWithKey,
        identity: &GroupIdentity,
        external_sender: &[u8; PUBLIC_KEY_LEN],
        key_packages: &[KeyPackage],
        roster: &impl Roster,
    ) -> Result<(Self, Commit), MlsError> {
        let config = create_config(external_sender)?;
        let inner = MlsGroup::new_with_group_id(
            provider,
            signer,
            &config,
            identity.to_group_id(),
            credential,
        )
        .map_err(library)?;
        let mut group = Self { inner };
        let commit = group.add(provider, signer, key_packages, roster)?;
        Ok((group, commit))
    }

    /// Adds devices, in a commit that stays pending. Each package must use
    /// Tavern's ciphersuite and pass the roster, and no device may end up
    /// with two leaves.
    pub fn add<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
        key_packages: &[KeyPackage],
        roster: &impl Roster,
    ) -> Result<Commit, MlsError> {
        let mut devices: HashSet<_> = self.devices().into_iter().collect();
        for key_package in key_packages {
            if key_package.ciphersuite() != CIPHERSUITE {
                return Err(MlsError::Parameters);
            }
            let leaf = key_package.leaf_node();
            let verified = verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), roster)?;
            if !devices.insert(verified) {
                return Err(LeafError::DuplicateDevice.into());
            }
        }
        let bundle = self
            .inner
            .commit_builder()
            .consume_proposal_store(false)
            .propose_adds(key_packages.iter().cloned())
            .load_psks(provider.storage())
            .map_err(library)?
            .create_group_info(true)
            // The filter applies to this commit's own proposals too: keep them.
            // The store is left out by `consume_proposal_store(false)`.
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .map_err(library)?
            .stage_commit(provider)
            .map_err(library)?;
        self.checked_own_commit(provider, bundle, roster)
    }

    /// Checks this device's pending commit like any other before it leaves.
    fn checked_own_commit<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        bundle: CommitMessageBundle,
        roster: &impl Roster,
    ) -> Result<Commit, MlsError> {
        let own = Sender::Member(self.inner.own_leaf_index());
        let checked = match self.inner.pending_commit() {
            Some(staged) => policy::check_commit(&self.inner, staged, &own, roster),
            None => return Err(MlsError::Malformed),
        };
        match checked {
            Ok(_) => commit_from_bundle(bundle),
            Err(alarm) => {
                self.discard_pending_commit(provider)?;
                Err(own_commit_error(alarm))
            }
        }
    }

    /// Joins a group from a Welcome. Every member must pass the roster, the
    /// group must use Tavern's ciphersuite, a Tavern group id, and the
    /// instance's key as its only external sender.
    pub fn join<P: OpenMlsProvider>(
        provider: &P,
        welcome: &[u8],
        roster: &impl Roster,
        external_sender: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(Self, Vec<VerifiedLeaf>), MlsError> {
        let MlsMessageBodyIn::Welcome(welcome) = parse(welcome)?.extract() else {
            return Err(MlsError::Malformed);
        };
        let staged = StagedWelcome::new_from_welcome(provider, &join_config(), welcome, None)
            .map_err(library)?;
        let context = staged.group_context();
        if context.ciphersuite() != CIPHERSUITE {
            return Err(MlsError::Parameters);
        }
        GroupIdentity::from_group_id(context.group_id())?;
        let expected = vec![server_external_sender(external_sender)];
        if context.extensions().external_senders() != Some(&expected) {
            return Err(MlsError::Parameters);
        }
        let members: Vec<_> = staged.members().collect();
        let verified = verify_members(
            members
                .iter()
                .map(|member| (&member.credential, member.signature_key.as_slice())),
            roster,
        )
        .map_err(Alarm::from)?;
        let inner = staged.into_group(provider).map_err(library)?;
        Ok((Self { inner }, verified))
    }

    /// Joins a group by external commit, from the GroupInfo the server keeps
    /// (section 5): a new device, or a device that lost its state or was
    /// removed (OpenMLS then removes its earlier leaf, which is the only
    /// removal an external commit may carry). The group is checked like a
    /// Welcome's; the commit is to be submitted, and the group dropped with
    /// [`Group::delete`] if the server refuses it.
    pub fn join_by_external_commit<P: OpenMlsProvider>(
        provider: &P,
        signer: &DeviceSigner<'_>,
        credential: CredentialWithKey,
        group_info: &[u8],
        roster: &impl Roster,
        external_sender: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(Self, Commit, Vec<VerifiedLeaf>), MlsError> {
        let MlsMessageBodyIn::GroupInfo(group_info) = parse(group_info)?.extract() else {
            return Err(MlsError::Malformed);
        };
        if group_info.ciphersuite() != CIPHERSUITE {
            return Err(MlsError::Parameters);
        }
        GroupIdentity::from_group_id(group_info.group_id())?;
        let (inner, bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config())
            .build_group(provider, group_info, credential)
            .map_err(library)?
            .load_psks(provider.storage())
            .map_err(library)?
            .create_group_info(true)
            // The filter applies to this commit's own proposals too: keep them.
            // The store is left out by `consume_proposal_store(false)`.
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .map_err(library)?
            .finalize(provider)
            .map_err(library)?;
        let group = Self { inner };
        let expected = vec![server_external_sender(external_sender)];
        let checked = if group.inner.extensions().external_senders() == Some(&expected) {
            let members: Vec<_> = group.inner.members().collect();
            verify_members(
                members
                    .iter()
                    .map(|member| (&member.credential, member.signature_key.as_slice())),
                roster,
            )
            .map_err(|error| MlsError::Alarm(error.into()))
        } else {
            Err(MlsError::Parameters)
        };
        match checked {
            Ok(verified) => Ok((group, commit_from_bundle(bundle)?, verified)),
            Err(error) => {
                group.delete(provider)?;
                Err(error)
            }
        }
    }

    /// Deletes the group's state: after leaving it, after the server refused
    /// an external commit, or when the conversation's group is recreated.
    pub fn delete<P: OpenMlsProvider>(mut self, provider: &P) -> Result<(), MlsError> {
        self.inner.delete(provider.storage()).map_err(library)
    }

    /// Which conversation and which generation.
    pub fn identity(&self) -> Result<GroupIdentity, MlsError> {
        GroupIdentity::from_group_id(self.inner.group_id())
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    /// The devices in the group, as named by their certificates (verified
    /// when they joined).
    pub fn devices(&self) -> Vec<VerifiedLeaf> {
        self.inner
            .members()
            .filter_map(|member| name_leaf(&member.credential))
            .collect()
    }

    /// This device's leaf.
    pub fn own_leaf(&self) -> LeafNodeIndex {
        self.inner.own_leaf_index()
    }

    /// The leaf of a device (user id and device id).
    pub fn leaf_of(
        &self,
        user_id: &[u8; ID_LEN],
        device_id: &[u8; ID_LEN],
    ) -> Option<LeafNodeIndex> {
        let wanted = VerifiedLeaf {
            user_id: *user_id,
            device_id: *device_id,
        };
        self.inner.members().find_map(|member| {
            (name_leaf(&member.credential) == Some(wanted)).then_some(member.index)
        })
    }

    /// Encrypts content for the current epoch, padded (section 8).
    pub fn encrypt<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
        content: &[u8],
    ) -> Result<Vec<u8>, MlsError> {
        let padded = padding::pad(content)?;
        let message = self
            .inner
            .create_message(provider, signer, &padded)
            .map_err(library)?;
        to_bytes(&message)
    }

    /// Processes a message from the conversation's sequence: decrypts
    /// content, stores the server's removal proposals, checks and merges
    /// commits. Nothing that fails the policy or a leaf check is stored or
    /// merged; a commit that fails is an alarm ([`MlsError::is_alarm`]).
    pub fn process<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        message: &[u8],
        roster: &impl Roster,
    ) -> Result<Incoming, MlsError> {
        let protocol: ProtocolMessage = parse(message)?
            .try_into_protocol_message()
            .map_err(|_| MlsError::Malformed)?;
        let processed = self
            .inner
            .process_message(provider, protocol)
            .map_err(processing_error)?;
        let sender = processed.sender().clone();
        let sender_leaf = name_leaf(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let bytes = application.into_bytes();
                Ok(Incoming::Application {
                    sender: sender_leaf,
                    content: padding::unpad(&bytes)?.to_vec(),
                })
            }
            ProcessedMessageContent::ProposalMessage(queued) => {
                policy::check_standalone(&queued)?;
                self.inner
                    .store_pending_proposal(provider.storage(), *queued)
                    .map_err(library)?;
                Ok(Incoming::Proposal)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(PolicyError::ExternalJoinProposal.into())
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let changes = policy::check_commit(&self.inner, &staged, &sender, roster)?;
                let self_removed = staged.self_removed();
                self.inner
                    .merge_staged_commit(provider, *staged)
                    .map_err(library)?;
                Ok(Incoming::Commit {
                    changes,
                    self_removed,
                })
            }
            ProcessedMessageContent::OwnPendingCommit => {
                self.merge_pending_commit(provider)?;
                Ok(Incoming::OwnCommit)
            }
            // The server does not send a device its own messages; if it
            // does, there is nothing to do.
            ProcessedMessageContent::OwnPrivateMessage => Ok(Incoming::OwnMessage),
        }
    }

    /// Commits an update of this device's leaf (section 9), pending. It
    /// carries no proposal.
    pub fn self_update<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
        roster: &impl Roster,
    ) -> Result<Commit, MlsError> {
        let bundle = self
            .inner
            .commit_builder()
            .consume_proposal_store(false)
            .force_self_update(true)
            .load_psks(provider.storage())
            .map_err(library)?
            .create_group_info(true)
            // The filter applies to this commit's own proposals too: keep them.
            // The store is left out by `consume_proposal_store(false)`.
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .map_err(library)?
            .stage_commit(provider)
            .map_err(library)?;
        self.checked_own_commit(provider, bundle, roster)
    }

    /// Commits the server's stored removal proposals (section 6), and
    /// nothing else, pending. `None` when none is stored.
    pub fn commit_pending_proposals<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
        roster: &impl Roster,
    ) -> Result<Option<Commit>, MlsError> {
        if !self.inner.pending_proposals().any(policy::committable) {
            return Ok(None);
        }
        let bundle = self
            .inner
            .commit_builder()
            .consume_proposal_store(true)
            .load_psks(provider.storage())
            .map_err(library)?
            .create_group_info(true)
            .build(
                provider.rand(),
                provider.crypto(),
                signer,
                policy::committable,
            )
            .map_err(library)?
            .stage_commit(provider)
            .map_err(library)?;
        self.checked_own_commit(provider, bundle, roster).map(Some)
    }

    /// Removes leaves, pending: devices of this user (a device it replaces),
    /// or leaves the server asked to remove. Anything else is refused.
    pub fn remove<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
        leaves: &[LeafNodeIndex],
        roster: &impl Roster,
    ) -> Result<Commit, MlsError> {
        let own_user = self
            .inner
            .own_leaf()
            .and_then(|leaf| name_leaf(leaf.credential()))
            .ok_or(MlsError::Malformed)?
            .user_id;
        let requested = policy::server_requested_removals(&self.inner);
        for leaf in leaves {
            let target = self
                .inner
                .member_at(*leaf)
                .and_then(|member| name_leaf(&member.credential));
            let allowed =
                target.map(|target| target.user_id) == Some(own_user) || requested.contains(leaf);
            if !allowed {
                return Err(PolicyError::RemoveNotAllowed.into());
            }
        }
        let bundle = self
            .inner
            .commit_builder()
            .consume_proposal_store(false)
            .propose_removals(leaves.iter().copied())
            .load_psks(provider.storage())
            .map_err(library)?
            .create_group_info(true)
            // The filter applies to this commit's own proposals too: keep them.
            // The store is left out by `consume_proposal_store(false)`.
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .map_err(library)?
            .stage_commit(provider)
            .map_err(library)?;
        self.checked_own_commit(provider, bundle, roster)
    }

    /// The server accepted this device's pending commit.
    pub fn merge_pending_commit<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
    ) -> Result<(), MlsError> {
        self.inner.merge_pending_commit(provider).map_err(library)
    }

    /// The server refused this device's pending commit (another commit took
    /// the epoch, section 7): it is dropped, never sent again unchanged.
    pub fn discard_pending_commit<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
    ) -> Result<(), MlsError> {
        self.inner
            .clear_pending_commit(provider.storage())
            .map_err(library)
    }

    /// The OpenMLS group, for tests that build what the wrapper never does.
    #[cfg(test)]
    pub(crate) fn inner_mut(&mut self) -> &mut MlsGroup {
        &mut self.inner
    }
}
