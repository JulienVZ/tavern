// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a client accepts in a group, beyond what MLS itself checks (ADR 0019,
//! sections 2, 5, 6 and 11).
//!
//! Received on their own, only the server's `Remove` proposals are stored:
//! a member never sends a proposal by itself in Tavern, it commits. In a
//! commit, only these proposals may appear:
//!
//! - from a member committer, by value: `Add` (every new leaf a verified
//!   device of a participant), `Remove` of a device of the committer's own
//!   user or of a leaf the server asked to remove, and a group context change
//!   that keeps the external senders;
//! - by reference: the server's `Remove` proposals;
//! - in an external commit: the `ExternalInit`, and at most one `Remove`,
//!   of an earlier leaf of the joining device itself (a resync).
//!
//! Everything else (`Update` proposals, `PreSharedKey`, `ReInit`, custom
//! proposals, member proposals by reference) is refused. A committer's new
//! path keeps its leaf on the same device, and no device has two leaves.
//! A device is the pair (user id, device id).

use std::collections::HashSet;

use openmls::prelude::{
    LeafNodeIndex, Member, MlsGroup, Proposal, ProposalOrRefType, QueuedProposal, Sender,
    StagedCommit,
};

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
    /// A member sent a proposal on its own, or one is referenced: members
    /// only commit.
    #[error("members do not send proposals on their own")]
    MemberProposal,
    /// A kind of proposal Tavern never uses (`Update`, `PreSharedKey`,
    /// `ReInit`, custom ones...).
    #[error("this kind of proposal is not accepted")]
    ForbiddenProposal,
    /// A member removed a device of another user that the server had not
    /// asked to remove.
    #[error("a member may only remove its own devices or those the server asked to remove")]
    RemoveNotAllowed,
    /// An external commit carried more than the joining device's own resync.
    #[error("an external commit may only remove an earlier leaf of the joining device")]
    ExternalCommitContent,
}

/// Something in a commit or a Welcome that must raise the alarm of section
/// 11: the commit is not merged, the conversation is marked broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Alarm {
    /// A leaf is not a verified device of a participant.
    #[error("{0}")]
    Leaf(#[from] LeafError),
    /// The commit breaks Tavern's policy.
    #[error("{0}")]
    Policy(#[from] PolicyError),
    /// The commit refers to a proposal this device does not have, refused
    /// earlier or never received.
    #[error("the commit refers to a proposal this device refused or never received")]
    UnknownProposal,
}

fn is_server_remove(queued: &QueuedProposal) -> bool {
    matches!(queued.sender(), Sender::External(_))
        && matches!(queued.proposal(), Proposal::Remove(_))
}

/// The leaves the server has asked to remove, from the stored proposals.
pub(crate) fn server_requested_removals(group: &MlsGroup) -> HashSet<LeafNodeIndex> {
    group
        .pending_proposals()
        .filter(|queued| is_server_remove(queued))
        .filter_map(|queued| match queued.proposal() {
            Proposal::Remove(remove) => Some(remove.removed()),
            _ => None,
        })
        .collect()
}

/// Whether a stored proposal is one this device may commit: the server's
/// removals, nothing else.
pub(crate) fn committable(queued: &QueuedProposal) -> bool {
    is_server_remove(queued)
}

/// Checks a proposal received on its own, before it is stored.
pub(crate) fn check_standalone(queued: &QueuedProposal) -> Result<(), PolicyError> {
    match queued.sender() {
        Sender::External(_) if matches!(queued.proposal(), Proposal::Remove(_)) => Ok(()),
        Sender::External(_) => Err(PolicyError::ExternalProposalNotRemove),
        Sender::NewMemberProposal => Err(PolicyError::ExternalJoinProposal),
        Sender::Member(_) | Sender::NewMemberCommit => Err(PolicyError::MemberProposal),
    }
}

fn member_leaf(member: &Member) -> Option<VerifiedLeaf> {
    name_leaf(&member.credential)
}

fn leaf_at(group: &MlsGroup, index: LeafNodeIndex) -> Option<VerifiedLeaf> {
    group.member_at(index).as_ref().and_then(member_leaf)
}

/// Checks a commit before it is merged, whoever made it (this device's own
/// commits are checked before they are submitted), and says who joins and
/// who leaves.
pub(crate) fn check_commit(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer: &Sender,
    roster: &impl Roster,
) -> Result<MembershipChanges, Alarm> {
    let mut added = Vec::new();

    // The committer's new leaf: the same device for a member, the joining
    // device for an external commit.
    let path_leaf = staged
        .update_path_leaf_node()
        .map(|leaf| verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), roster))
        .transpose()?;
    let committer_leaf = match committer {
        Sender::Member(index) => {
            let before = leaf_at(group, *index).ok_or(LeafError::Malformed)?;
            if let Some(after) = path_leaf
                && after != before
            {
                return Err(LeafError::DeviceChanged.into());
            }
            before
        }
        Sender::NewMemberCommit => {
            let joiner = path_leaf.ok_or(PolicyError::ExternalCommitContent)?;
            added.push(joiner);
            joiner
        }
        Sender::External(_) | Sender::NewMemberProposal => {
            return Err(PolicyError::ExternalCommitContent.into());
        }
    };
    let external_commit = matches!(committer, Sender::NewMemberCommit);
    let requested = server_requested_removals(group);

    let mut removed_indexes = HashSet::new();
    for queued in staged.queued_proposals() {
        let by_reference = queued.proposal_or_ref_type() == ProposalOrRefType::Reference;
        match queued.proposal() {
            Proposal::Remove(remove) => {
                let target = remove.removed();
                let target_leaf = leaf_at(group, target);
                let allowed = if is_server_remove(queued) {
                    by_reference
                } else if external_commit {
                    // At most one, of an earlier leaf of the joining device.
                    removed_indexes.is_empty() && target_leaf == Some(committer_leaf)
                } else {
                    !by_reference
                        && (target_leaf.map(|leaf| leaf.user_id) == Some(committer_leaf.user_id)
                            || requested.contains(&target))
                };
                if !allowed {
                    return Err(if external_commit {
                        PolicyError::ExternalCommitContent
                    } else if by_reference && !is_server_remove(queued) {
                        PolicyError::MemberProposal
                    } else {
                        PolicyError::RemoveNotAllowed
                    }
                    .into());
                }
                removed_indexes.insert(target);
            }
            Proposal::Add(add) if !external_commit && !by_reference => {
                let leaf = add.key_package().leaf_node();
                added.push(verify_leaf(
                    leaf.credential(),
                    leaf.signature_key().as_slice(),
                    roster,
                )?);
            }
            Proposal::GroupContextExtensions(change) if !external_commit && !by_reference => {
                if change.extensions().external_senders() != group.extensions().external_senders() {
                    return Err(PolicyError::ExternalSendersChange.into());
                }
            }
            Proposal::ExternalInit(_) if external_commit => {}
            _ if by_reference && !matches!(queued.sender(), Sender::External(_)) => {
                return Err(PolicyError::MemberProposal.into());
            }
            _ if matches!(queued.sender(), Sender::External(_)) => {
                return Err(PolicyError::ExternalProposalNotRemove.into());
            }
            _ if external_commit => return Err(PolicyError::ExternalCommitContent.into()),
            _ => return Err(PolicyError::ForbiddenProposal.into()),
        }
    }

    let removed: Vec<VerifiedLeaf> = removed_indexes
        .iter()
        .filter_map(|index| leaf_at(group, *index))
        .collect();

    // After the commit, no device may have two leaves.
    let mut devices = HashSet::new();
    let remaining = group
        .members()
        .filter(|member| !removed_indexes.contains(&member.index))
        .filter_map(|member| member_leaf(&member));
    for leaf in remaining.chain(added.iter().copied()) {
        if !devices.insert(leaf) {
            return Err(LeafError::DuplicateDevice.into());
        }
    }

    Ok(MembershipChanges { added, removed })
}
