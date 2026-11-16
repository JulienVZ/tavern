// SPDX-License-Identifier: AGPL-3.0-or-later

//! A Tavern MLS group: one per conversation (ADR 0019, sections 4 to 9).
//!
//! Every method takes the OpenMLS provider whose storage holds the group's
//! state, so that the caller decides where and in which transaction it is
//! written (section 13). Commits created here stay pending until the server
//! accepts them ([`Group::merge_pending_commit`]) or refuses them
//! ([`Group::discard_pending_commit`]), as section 7 requires.

use openmls::prelude::tls_codec::{DeserializeBytes, Serialize as _};
use openmls::prelude::{
    CredentialWithKey, KeyPackage, LeafNodeIndex, LeafNodeParameters, MlsGroup, MlsMessageBodyIn,
    MlsMessageIn, MlsMessageOut, ProcessedMessageContent, ProtocolMessage, StagedWelcome,
};
use openmls_traits::OpenMlsProvider;

use std::collections::HashSet;

use super::credential::{LeafError, Roster, VerifiedLeaf, verify_leaf, verify_members};
use super::group_id::GroupIdentity;
use super::{
    CIPHERSUITE, DeviceSigner, MlsError, create_config, join_config, library, padding, policy,
    server_external_sender,
};
use crate::identity::PUBLIC_KEY_LEN;

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
    /// A proposal, checked and stored: a later commit will refer to it. The
    /// server's `Remove` proposals arrive this way.
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
        for key_package in key_packages {
            if key_package.ciphersuite() != CIPHERSUITE {
                return Err(MlsError::Parameters);
            }
        }
        let mut devices: HashSet<_> = self.devices().iter().map(|leaf| leaf.device_id).collect();
        for key_package in key_packages {
            let leaf = key_package.leaf_node();
            let verified = verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), roster)?;
            if !devices.insert(verified.device_id) {
                return Err(LeafError::DuplicateDevice.into());
            }
        }
        let (commit, welcome, group_info) = self
            .inner
            .add_members(provider, signer, key_packages)
            .map_err(library)?;
        Ok(Commit {
            commit: to_bytes(&commit)?,
            welcome: Some(to_bytes(&welcome)?),
            group_info: group_info
                .ok_or(MlsError::Malformed)
                .and_then(|info| to_bytes(&MlsMessageOut::from(info)))?,
        })
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
        )?;
        let inner = staged.into_group(provider).map_err(library)?;
        Ok((Self { inner }, verified))
    }

    /// The OpenMLS group, for tests that build what the wrapper never does.
    #[cfg(test)]
    pub(crate) fn inner_mut(&mut self) -> &mut MlsGroup {
        &mut self.inner
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
            .filter_map(|member| super::credential::name_leaf(&member.credential))
            .collect()
    }

    /// This device's leaf.
    pub fn own_leaf(&self) -> LeafNodeIndex {
        self.inner.own_leaf_index()
    }

    /// The leaf of a device, to remove it.
    pub fn leaf_of(&self, device_id: &[u8; crate::identity::ID_LEN]) -> Option<LeafNodeIndex> {
        self.inner.members().find_map(|member| {
            super::credential::name_leaf(&member.credential)
                .filter(|leaf| leaf.device_id == *device_id)
                .map(|_| member.index)
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
    /// content, checks and stores proposals, checks and merges commits.
    /// Nothing that fails the policy or a leaf check is stored or merged.
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
            .map_err(library)?;
        let sender = processed.sender().clone();
        let sender_leaf = super::credential::name_leaf(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let bytes = application.into_bytes();
                Ok(Incoming::Application {
                    sender: sender_leaf,
                    content: padding::unpad(&bytes)?.to_vec(),
                })
            }
            ProcessedMessageContent::ProposalMessage(queued) => {
                policy::check_queued(&self.inner, &queued)?;
                self.inner
                    .store_pending_proposal(provider.storage(), *queued)
                    .map_err(library)?;
                Ok(Incoming::Proposal)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(policy::PolicyError::ExternalJoinProposal.into())
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

    /// Commits an update of this device's leaf (section 9), pending.
    pub fn self_update<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
    ) -> Result<Commit, MlsError> {
        let bundle = self
            .inner
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(library)?;
        // An update adds nobody: there is no Welcome.
        let (commit, _, group_info) = bundle.into_contents();
        Ok(Commit {
            commit: to_bytes(&commit)?,
            welcome: None,
            group_info: group_info
                .ok_or(MlsError::Malformed)
                .and_then(|info| to_bytes(&MlsMessageOut::from(info)))?,
        })
    }

    /// Commits the stored proposals, the server's removals first among them
    /// (section 6), pending. `None` when nothing is pending.
    pub fn commit_pending_proposals<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
    ) -> Result<Option<Commit>, MlsError> {
        if self.inner.pending_proposals().next().is_none() {
            return Ok(None);
        }
        let (commit, welcome, group_info) = self
            .inner
            .commit_to_pending_proposals(provider, signer)
            .map_err(library)?;
        Ok(Some(Commit {
            commit: to_bytes(&commit)?,
            welcome: welcome.as_ref().map(to_bytes).transpose()?,
            group_info: group_info
                .ok_or(MlsError::Malformed)
                .and_then(|info| to_bytes(&MlsMessageOut::from(info)))?,
        }))
    }

    /// Removes devices of this user (a device it replaces), pending.
    pub fn remove<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
        leaves: &[LeafNodeIndex],
    ) -> Result<Commit, MlsError> {
        let (commit, welcome, group_info) = self
            .inner
            .remove_members(provider, signer, leaves)
            .map_err(library)?;
        Ok(Commit {
            commit: to_bytes(&commit)?,
            welcome: welcome.as_ref().map(to_bytes).transpose()?,
            group_info: group_info
                .ok_or(MlsError::Malformed)
                .and_then(|info| to_bytes(&MlsMessageOut::from(info)))?,
        })
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
}
