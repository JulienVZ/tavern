// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a client accepts in a group, beyond what MLS itself checks (ADR 0019,
//! sections 2, 6 and 11).
//!
//! - From an external sender (the server), only `Remove` proposals.
//! - No proposal that changes the group's external senders.
//! - No external join proposal (new devices join by external commit).
//! - Every leaf a commit adds or changes is a verified device of a
//!   participant; an update keeps its device; no device has two leaves.

use std::collections::HashSet;

use openmls::prelude::{Member, MlsGroup, Proposal, QueuedProposal, Sender, StagedCommit};

use super::MembershipChanges;
use super::credential::{LeafError, Roster, VerifiedLeaf, name_leaf, verify_leaf};

/// Why a handshake message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// An external sender proposed something else than `Remove`.
    #[error("the server may only propose removals")]
    ExternalProposalNotRemove,
    /// A proposal would change the group's external senders.
    #[error("the group's external senders may not change")]
    ExternalSendersChange,
    /// An external join proposal: Tavern devices join by external commit.
    #[error("external join proposals are not accepted")]
    ExternalJoinProposal,
}

/// Checks a proposal received on its own, or carried by a commit.
pub(crate) fn check_proposal(
    group: &MlsGroup,
    sender: &Sender,
    proposal: &Proposal,
) -> Result<(), PolicyError> {
    match sender {
        Sender::External(_) if !matches!(proposal, Proposal::Remove(_)) => {
            return Err(PolicyError::ExternalProposalNotRemove);
        }
        Sender::NewMemberProposal => return Err(PolicyError::ExternalJoinProposal),
        _ => {}
    }
    if let Proposal::GroupContextExtensions(change) = proposal
        && change.extensions().external_senders() != group.extensions().external_senders()
    {
        return Err(PolicyError::ExternalSendersChange);
    }
    Ok(())
}

/// Checks a received proposal before it is stored.
pub(crate) fn check_queued(group: &MlsGroup, queued: &QueuedProposal) -> Result<(), PolicyError> {
    check_proposal(group, queued.sender(), queued.proposal())
}

fn member_leaf(member: &Member) -> Option<VerifiedLeaf> {
    name_leaf(&member.credential)
}

/// Checks a commit before it is merged, and says who joins and who leaves.
///
/// A leaf that fails is an error: the caller must not merge the commit, and
/// marks the conversation broken (section 11).
pub(crate) fn check_commit(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer: &Sender,
    roster: &impl Roster,
) -> Result<MembershipChanges, super::MlsError> {
    for queued in staged.queued_proposals() {
        check_proposal(group, queued.sender(), queued.proposal())?;
    }

    let mut added = Vec::new();
    for add in staged.add_proposals() {
        let leaf = add.add_proposal().key_package().leaf_node();
        added.push(verify_leaf(
            leaf.credential(),
            leaf.signature_key().as_slice(),
            roster,
        )?);
    }

    // An updated leaf, by proposal or by the committer's path, stays the
    // same device; an external committer is a new leaf.
    let mut updated = Vec::new();
    for update in staged.update_proposals() {
        let Sender::Member(index) = update.sender() else {
            return Err(LeafError::DeviceChanged.into());
        };
        let leaf = update.update_proposal().leaf_node();
        let verified = verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), roster)?;
        updated.push((*index, verified));
    }
    if let Some(leaf) = staged.update_path_leaf_node() {
        let verified = verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), roster)?;
        match committer {
            Sender::Member(index) => updated.push((*index, verified)),
            Sender::NewMemberCommit => added.push(verified),
            _ => {}
        }
    }
    for (index, verified) in &updated {
        let before = group.member_at(*index).as_ref().and_then(member_leaf);
        if before.map(|leaf| leaf.device_id) != Some(verified.device_id) {
            return Err(LeafError::DeviceChanged.into());
        }
    }

    let removed_indexes: HashSet<_> = staged
        .remove_proposals()
        .map(|remove| remove.remove_proposal().removed())
        .collect();
    let removed: Vec<VerifiedLeaf> = removed_indexes
        .iter()
        .filter_map(|index| group.member_at(*index).as_ref().and_then(member_leaf))
        .collect();

    // After the commit, no device may have two leaves.
    let mut devices = HashSet::new();
    let remaining = group
        .members()
        .filter(|member| !removed_indexes.contains(&member.index))
        .filter_map(|member| member_leaf(&member));
    for leaf in remaining.chain(added.iter().copied()) {
        if !devices.insert(leaf.device_id) {
            return Err(LeafError::DuplicateDevice.into());
        }
    }

    Ok(MembershipChanges { added, removed })
}
