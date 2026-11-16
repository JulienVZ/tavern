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
    CommitMessageBundle, CredentialWithKey, KeyPackageBundle, KeyPackageRef, LeafNodeIndex,
    MlsGroup, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent,
    ProtocolMessage, ProtocolVersion, Sender, StagedWelcome, Welcome,
};
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::StorageProvider as _;

use super::credential::{LeafError, Roster, VerifiedLeaf, name_leaf, verify_leaf, verify_members};
use super::group_id::GroupIdentity;
use super::key_package::ClaimedKeyPackage;
use super::policy::{self, Alarm, PolicyError};
use super::{
    CIPHERSUITE, DeviceSigner, MlsError, create_config, join_config, library, padding,
    processing_error, required_capabilities, server_external_sender,
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

/// The group a device expects to create or join: which conversation and
/// generation, and which users take part. Anything else is refused, such as
/// an old Welcome replayed after the group was recreated.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedGroup<'a> {
    /// The conversation and generation.
    pub identity: GroupIdentity,
    /// The users of the conversation; each must have a device in the group,
    /// and nobody else may.
    pub participants: &'a [[u8; ID_LEN]],
}

impl ExpectedGroup<'_> {
    fn check_members(&self, members: &[VerifiedLeaf]) -> Result<(), MlsError> {
        let users: HashSet<_> = members.iter().map(|leaf| leaf.user_id).collect();
        if users.iter().any(|user| !self.participants.contains(user)) {
            return Err(Alarm::Leaf(LeafError::NotParticipant).into());
        }
        if self.participants.iter().any(|user| !users.contains(user)) {
            return Err(MlsError::UnexpectedGroup);
        }
        Ok(())
    }
}

/// A group joined by Welcome.
#[derive(Debug)]
pub struct Joined {
    /// The group.
    pub group: Group,
    /// Its devices, all verified.
    pub members: Vec<VerifiedLeaf>,
    /// The Welcome used this device's last-resort KeyPackage. It has been
    /// deleted: upload a new one (section 3).
    pub last_resort_used: bool,
}

/// A Tavern MLS group.
#[derive(Debug)]
pub struct Group {
    inner: MlsGroup,
}

/// This device's KeyPackage that a Welcome is for, if it has it, and whether
/// it is the last-resort one.
fn own_key_package<P: OpenMlsProvider>(
    provider: &P,
    welcome: &Welcome,
) -> Result<Option<(KeyPackageRef, bool)>, MlsError> {
    for secrets in welcome.secrets() {
        let reference = secrets.new_member();
        let bundle: Option<KeyPackageBundle> = provider
            .storage()
            .key_package(&reference)
            .map_err(library)?;
        if let Some(bundle) = bundle {
            return Ok(Some((reference, bundle.key_package().last_resort())));
        }
    }
    Ok(None)
}

/// Checks the parameters of a group to join: ciphersuite, id, the
/// instance's key as the only external sender, required capabilities.
fn check_context(
    ciphersuite: openmls::prelude::Ciphersuite,
    group_id: &openmls::prelude::GroupId,
    extensions: &openmls::prelude::Extensions<openmls::prelude::GroupContext>,
    expected: &ExpectedGroup<'_>,
    external_sender: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), MlsError> {
    if ciphersuite != CIPHERSUITE {
        return Err(MlsError::Parameters);
    }
    if *group_id != expected.identity.to_group_id() {
        return Err(MlsError::UnexpectedGroup);
    }
    let senders = vec![server_external_sender(external_sender)];
    if extensions.external_senders() != Some(&senders) {
        return Err(MlsError::Parameters);
    }
    if extensions.required_capabilities() != Some(&required_capabilities()) {
        return Err(MlsError::Parameters);
    }
    Ok(())
}

fn check_group_context(
    context: &openmls::prelude::GroupContext,
    expected: &ExpectedGroup<'_>,
    external_sender: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), MlsError> {
    check_context(
        context.ciphersuite(),
        context.group_id(),
        context.extensions(),
        expected,
        external_sender,
    )
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

/// Checks claimed KeyPackages before they are added: each passes the roster
/// again (it may differ from the one used at claim time), and no device
/// appears twice, among them or with `present`.
fn check_key_packages(
    key_packages: &[ClaimedKeyPackage],
    roster: &impl Roster,
    present: &[VerifiedLeaf],
) -> Result<Vec<VerifiedLeaf>, MlsError> {
    let mut devices: HashSet<_> = present.iter().copied().collect();
    let mut verified = Vec::with_capacity(key_packages.len());
    for claimed in key_packages {
        let leaf = claimed.key_package().leaf_node();
        let device = verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), roster)?;
        if !devices.insert(device) {
            return Err(LeafError::DuplicateDevice.into());
        }
        verified.push(device);
    }
    Ok(verified)
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
    /// which stays pending. Everything is checked before anything is written:
    /// every device passes the roster (the server hands the packages out,
    /// and could slip in a device of its own), no device appears twice, and
    /// the devices are exactly those of the expected participants.
    pub fn create<P: OpenMlsProvider>(
        provider: &P,
        signer: &DeviceSigner<'_>,
        credential: CredentialWithKey,
        expected: &ExpectedGroup<'_>,
        external_sender: &[u8; PUBLIC_KEY_LEN],
        key_packages: &[ClaimedKeyPackage],
        roster: &impl Roster,
    ) -> Result<(Self, Commit), MlsError> {
        let own = verify_leaf(
            &credential.credential,
            credential.signature_key.as_slice(),
            roster,
        )?;
        let mut members = vec![own];
        members.extend(check_key_packages(key_packages, roster, &[own])?);
        expected
            .check_members(&members)
            .map_err(|error| match error {
                MlsError::Alarm(Alarm::Leaf(leaf)) => MlsError::Leaf(leaf),
                other => other,
            })?;

        let config = create_config(external_sender)?;
        let inner = MlsGroup::new_with_group_id(
            provider,
            signer,
            &config,
            expected.identity.to_group_id(),
            credential,
        )
        .map_err(library)?;
        let mut group = Self { inner };
        let commit = group.add(provider, signer, key_packages, roster)?;
        Ok((group, commit))
    }

    /// Adds devices, in a commit that stays pending. Each package must pass
    /// the roster, and no device may end up with two leaves.
    pub fn add<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &DeviceSigner<'_>,
        key_packages: &[ClaimedKeyPackage],
        roster: &impl Roster,
    ) -> Result<Commit, MlsError> {
        check_key_packages(key_packages, roster, &self.devices())?;
        let bundle = self
            .inner
            .commit_builder()
            .consume_proposal_store(false)
            .propose_adds(
                key_packages
                    .iter()
                    .map(|claimed| claimed.key_package().clone()),
            )
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

    /// Joins a group from a Welcome. It must be the expected group (its
    /// conversation, generation and participants), with Tavern's parameters,
    /// and every member must pass the roster. A used last-resort KeyPackage
    /// is deleted (section 3): an old Welcome cannot be replayed with it.
    pub fn join<P: OpenMlsProvider>(
        provider: &P,
        welcome: &[u8],
        expected: &ExpectedGroup<'_>,
        roster: &impl Roster,
        external_sender: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Joined, MlsError> {
        let MlsMessageBodyIn::Welcome(welcome) = parse(welcome)?.extract() else {
            return Err(MlsError::Malformed);
        };
        let own = own_key_package(provider, &welcome)?;
        let staged = StagedWelcome::new_from_welcome(provider, &join_config(), welcome, None)
            .map_err(|error| match error {
                // Not for one of this device's KeyPackages (deleted after
                // use, or never ours), or for a group it is already in.
                openmls::prelude::WelcomeError::NoMatchingKeyPackage
                | openmls::prelude::WelcomeError::GroupAlreadyExists => MlsError::UnexpectedGroup,
                other => library(other),
            })?;
        check_group_context(staged.group_context(), expected, external_sender)?;
        let members: Vec<_> = staged.members().collect();
        let members = verify_members(
            members
                .iter()
                .map(|member| (&member.credential, member.signature_key.as_slice())),
            roster,
        )
        .map_err(Alarm::from)?;
        expected.check_members(&members)?;
        let inner = staged.into_group(provider).map_err(library)?;
        let last_resort_used = match own {
            Some((reference, true)) => {
                provider
                    .storage()
                    .delete_key_package(&reference)
                    .map_err(library)?;
                true
            }
            _ => false,
        };
        Ok(Joined {
            group: Self { inner },
            members,
            last_resort_used,
        })
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
        expected: &ExpectedGroup<'_>,
        roster: &impl Roster,
        external_sender: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(Self, Commit, Vec<VerifiedLeaf>), MlsError> {
        let MlsMessageBodyIn::GroupInfo(group_info) = parse(group_info)?.extract() else {
            return Err(MlsError::Malformed);
        };
        check_group_context(group_info.group_context(), expected, external_sender)?;
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
        let checked = check_context(
            group.inner.ciphersuite(),
            group.inner.group_id(),
            group.inner.extensions(),
            expected,
            external_sender,
        )
        .and_then(|()| {
            let members: Vec<_> = group.inner.members().collect();
            verify_members(
                members
                    .iter()
                    .map(|member| (&member.credential, member.signature_key.as_slice())),
                roster,
            )
            .map_err(|error| MlsError::Alarm(error.into()))
        })
        .and_then(|members| expected.check_members(&members).map(|()| members));
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
