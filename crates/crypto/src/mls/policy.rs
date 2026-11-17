// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a client accepts in a group, beyond what MLS itself checks (ADR 0019,
//! sections 2, 5, 6 and 11).
//!
//! Received on their own, only the server's `Remove` proposals are stored:
//! a member never sends a proposal by itself in Tavern, it commits. In a
//! commit, only these proposals may appear:
//!
//! - from a member committer, by value: `Add` (every new leaf a verified
//!   device of a participant), and `Remove` of a device of the committer's
//!   own user or of a leaf the server asked to remove;
//! - from a member committer, by reference: the server's `Remove` proposals;
//! - in an external commit: the `ExternalInit`, and at most one `Remove`, by
//!   value, of an earlier leaf of the joining device itself (a resync).
//!   Nothing by reference, not even the server's removals.
//!
//! Everything else (`Update` proposals, group context changes, which Tavern
//! never makes, `PreSharedKey`, `ReInit`, custom proposals, member proposals
//! by reference) is refused. A committer's new path keeps its leaf on the
//! same device, no device has two leaves, and a device never changes its
//! signature key. A device is the pair (user id, device id).

use std::collections::{HashMap, HashSet};

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
    /// An external join proposal: Tavern devices join by external commit.
    #[error("external join proposals are not accepted")]
    ExternalJoinProposal,
    /// A member sent a proposal on its own, or one is referenced: members
    /// only commit.
    #[error("members do not send proposals on their own")]
    MemberProposal,
    /// A kind of proposal Tavern never uses (`Update`, group context
    /// changes, `PreSharedKey`, `ReInit`, custom ones...).
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
    /// OpenMLS refuses a commit the server accepted, for a reason the server
    /// could check on the group's public state, or that no state of this
    /// device explains (ADR 0019, section 11). OpenMLS's message, which
    /// carries no secret.
    #[error("the server accepted an invalid commit: {0}")]
    InvalidCommit(String),
}

fn is_server_remove(queued: &QueuedProposal) -> bool {
    matches!(queued.sender(), Sender::External(_))
        && matches!(queued.proposal(), Proposal::Remove(_))
}

/// The leaves the server has asked to remove, among stored proposals.
pub(crate) fn requested_by_server<'a>(
    proposals: impl IntoIterator<Item = &'a QueuedProposal>,
) -> HashSet<LeafNodeIndex> {
    proposals
        .into_iter()
        .filter(|queued| is_server_remove(queued))
        .filter_map(|queued| match queued.proposal() {
            Proposal::Remove(remove) => Some(remove.removed()),
            _ => None,
        })
        .collect()
}

/// The leaves the server has asked to remove, from a member's stored
/// proposals.
pub(crate) fn server_requested_removals(group: &MlsGroup) -> HashSet<LeafNodeIndex> {
    group.requested_removals()
}

/// What the policy reads of a group: a member's `MlsGroup` on a client, the
/// `PublicGroup` on the server, which applies the same rules.
pub(crate) trait GroupView {
    /// The device of the leaf at `index`, if the leaf is not blank.
    fn device_at(&self, index: LeafNodeIndex) -> Option<VerifiedLeaf>;
    /// The devices of the group, with their leaves.
    fn leaves(&self) -> Vec<(LeafNodeIndex, VerifiedLeaf)>;
    /// The signature key of the leaf at `index`.
    fn signature_key(&self, index: LeafNodeIndex) -> Option<Vec<u8>>;
    /// The leaves the server has asked to remove, from the stored proposals.
    fn requested_removals(&self) -> HashSet<LeafNodeIndex>;
}

impl GroupView for MlsGroup {
    fn device_at(&self, index: LeafNodeIndex) -> Option<VerifiedLeaf> {
        self.member_at(index).as_ref().and_then(member_leaf)
    }

    fn leaves(&self) -> Vec<(LeafNodeIndex, VerifiedLeaf)> {
        named_leaves(self.members())
    }

    fn signature_key(&self, index: LeafNodeIndex) -> Option<Vec<u8>> {
        self.member_at(index).map(|member| member.signature_key)
    }

    fn requested_removals(&self) -> HashSet<LeafNodeIndex> {
        requested_by_server(self.pending_proposals())
    }
}

pub(crate) fn named_leaves(
    members: impl Iterator<Item = Member>,
) -> Vec<(LeafNodeIndex, VerifiedLeaf)> {
    members
        .filter_map(|member| member_leaf(&member).map(|leaf| (member.index, leaf)))
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

/// Who made a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Committer {
    /// A member: the device of its leaf.
    Member(VerifiedLeaf),
    /// A device joining by external commit.
    Joiner(VerifiedLeaf),
}

/// A proposal of a commit, as the policy sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    kind: Kind,
    /// Included by reference (received and stored earlier), not by value.
    by_reference: bool,
    /// Sent by the external sender, the server.
    from_server: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Removes the leaf `index`, of the device `device` if it names one.
    Remove {
        index: LeafNodeIndex,
        device: Option<VerifiedLeaf>,
    },
    /// Adds a leaf: its device, or why the roster refuses it.
    Add(Result<VerifiedLeaf, LeafError>),
    /// The `ExternalInit` of an external commit.
    ExternalInit,
    /// Anything else: `Update`, group context changes, `PreSharedKey`,
    /// `ReInit`, custom proposals...
    Other,
}

fn entry(group: &impl GroupView, queued: &QueuedProposal, roster: &impl Roster) -> Entry {
    let kind = match queued.proposal() {
        Proposal::Remove(remove) => Kind::Remove {
            index: remove.removed(),
            device: group.device_at(remove.removed()),
        },
        Proposal::Add(add) => {
            let leaf = add.key_package().leaf_node();
            Kind::Add(verify_leaf(
                leaf.credential(),
                leaf.signature_key().as_slice(),
                roster,
            ))
        }
        Proposal::ExternalInit(_) => Kind::ExternalInit,
        _ => Kind::Other,
    };
    Entry {
        kind,
        by_reference: queued.proposal_or_ref_type() == ProposalOrRefType::Reference,
        from_server: matches!(queued.sender(), Sender::External(_)),
    }
}

/// Checks the proposals of a commit, in order: the devices they add, and
/// the leaves they remove, in order. `requested` are the leaves the server
/// has asked to remove.
fn check_proposals(
    committer: Committer,
    entries: &[Entry],
    requested: &HashSet<LeafNodeIndex>,
) -> Result<(Vec<VerifiedLeaf>, Vec<LeafNodeIndex>), Alarm> {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    for entry in entries {
        match committer {
            // Section 5: decided first, so that nothing an external commit
            // carries goes through a member's rules.
            Committer::Joiner(joiner) => match entry.kind {
                _ if entry.by_reference => return Err(PolicyError::ExternalCommitContent.into()),
                Kind::ExternalInit => {}
                Kind::Remove { index, device } if removed.is_empty() && device == Some(joiner) => {
                    removed.push(index);
                }
                _ => return Err(PolicyError::ExternalCommitContent.into()),
            },
            // Stored earlier, so the server's removal (`check_standalone`).
            Committer::Member(_) if entry.from_server => match entry.kind {
                Kind::Remove { index, .. } => removed.push(index),
                _ => return Err(PolicyError::ExternalProposalNotRemove.into()),
            },
            Committer::Member(_) if entry.by_reference => {
                return Err(PolicyError::MemberProposal.into());
            }
            Committer::Member(member) => match entry.kind {
                Kind::Remove { index, device } => {
                    let own_user = device.map(|device| device.user_id) == Some(member.user_id);
                    if !own_user && !requested.contains(&index) {
                        return Err(PolicyError::RemoveNotAllowed.into());
                    }
                    removed.push(index);
                }
                Kind::Add(device) => added.push(device?),
                Kind::ExternalInit | Kind::Other => {
                    return Err(PolicyError::ForbiddenProposal.into());
                }
            },
        }
    }
    Ok((added, removed))
}

/// A device never changes its signature key (section 2): every new leaf of a
/// device the group holds before the commit carries the key it holds it
/// with, a resync included. `before` maps the group's devices to their keys.
fn check_keys(
    before: &HashMap<VerifiedLeaf, Vec<u8>>,
    new_leaves: &[(VerifiedLeaf, Vec<u8>)],
) -> Result<(), LeafError> {
    for (device, key) in new_leaves {
        if before.get(device).is_some_and(|known| known != key) {
            return Err(LeafError::KeyChanged);
        }
    }
    Ok(())
}

/// Checks a commit before it is merged, whoever made it (this device's own
/// commits are checked before they are submitted), and says who joins and
/// who leaves.
pub(crate) fn check_commit(
    group: &impl GroupView,
    staged: &StagedCommit,
    committer: &Sender,
    roster: &impl Roster,
) -> Result<MembershipChanges, Alarm> {
    // The committer's new leaf: the same device for a member, the joining
    // device for an external commit.
    let path_leaf = staged
        .update_path_leaf_node()
        .map(|leaf| verify_leaf(leaf.credential(), leaf.signature_key().as_slice(), roster))
        .transpose()?;
    let committer = match committer {
        Sender::Member(index) => {
            let before = group.device_at(*index).ok_or(LeafError::Malformed)?;
            if let Some(after) = path_leaf
                && after != before
            {
                return Err(LeafError::DeviceChanged.into());
            }
            Committer::Member(before)
        }
        Sender::NewMemberCommit => {
            Committer::Joiner(path_leaf.ok_or(PolicyError::ExternalCommitContent)?)
        }
        Sender::External(_) | Sender::NewMemberProposal => {
            return Err(PolicyError::ExternalCommitContent.into());
        }
    };

    let entries: Vec<Entry> = staged
        .queued_proposals()
        .map(|queued| entry(group, queued, roster))
        .collect();
    let (mut added, removed_indexes) =
        check_proposals(committer, &entries, &group.requested_removals())?;
    if let Committer::Joiner(joiner) = committer {
        added.insert(0, joiner);
    }
    let removed: Vec<VerifiedLeaf> = removed_indexes
        .iter()
        .filter_map(|index| group.device_at(*index))
        .collect();

    // The new leaves keep their devices' keys.
    let before: HashMap<VerifiedLeaf, Vec<u8>> = group
        .leaves()
        .into_iter()
        .filter_map(|(index, leaf)| group.signature_key(index).map(|key| (leaf, key)))
        .collect();
    let mut new_leaves = Vec::new();
    if let (Some(device), Some(leaf)) = (path_leaf, staged.update_path_leaf_node()) {
        new_leaves.push((device, leaf.signature_key().as_slice().to_vec()));
    }
    for queued in staged.queued_proposals() {
        if let Proposal::Add(add) = queued.proposal() {
            let leaf = add.key_package().leaf_node();
            if let Some(device) = name_leaf(leaf.credential()) {
                new_leaves.push((device, leaf.signature_key().as_slice().to_vec()));
            }
        }
    }
    check_keys(&before, &new_leaves)?;

    // After the commit, no device may have two leaves.
    let mut devices = HashSet::new();
    let remaining = group
        .leaves()
        .into_iter()
        .filter(|(index, _)| !removed_indexes.contains(index))
        .map(|(_, leaf)| leaf);
    for leaf in remaining.chain(added.iter().copied()) {
        if !devices.insert(leaf) {
            return Err(LeafError::DuplicateDevice.into());
        }
    }

    Ok(MembershipChanges { added, removed })
}

#[cfg(test)]
mod tests {
    //! The decisions of [`check_proposals`], case by case. The commits that
    //! honest OpenMLS clients can build are tested end to end in
    //! `mls::tests`; some of these (an external commit referring to a stored
    //! proposal) cannot be built through OpenMLS's API, yet a receiver's
    //! OpenMLS would accept them, so the policy is tested here directly.

    use super::*;

    const ALICE: [u8; 16] = [1; 16];
    const BOB: [u8; 16] = [2; 16];

    fn device(user_id: [u8; 16], device: u8) -> VerifiedLeaf {
        VerifiedLeaf {
            user_id,
            device_id: [device; 16],
        }
    }

    fn by_value(kind: Kind) -> Entry {
        Entry {
            kind,
            by_reference: false,
            from_server: false,
        }
    }

    fn by_reference(kind: Kind) -> Entry {
        Entry {
            kind,
            by_reference: true,
            from_server: false,
        }
    }

    fn from_server(kind: Kind) -> Entry {
        Entry {
            kind,
            by_reference: true,
            from_server: true,
        }
    }

    fn remove(index: u32, device: VerifiedLeaf) -> Kind {
        Kind::Remove {
            index: LeafNodeIndex::new(index),
            device: Some(device),
        }
    }

    fn leaves(indexes: &[u32]) -> Vec<LeafNodeIndex> {
        indexes.iter().copied().map(LeafNodeIndex::new).collect()
    }

    fn check(
        committer: Committer,
        entries: &[Entry],
        requested: &[u32],
    ) -> Result<(Vec<VerifiedLeaf>, Vec<LeafNodeIndex>), Alarm> {
        check_proposals(committer, entries, &leaves(requested).into_iter().collect())
    }

    const EXTERNAL_COMMIT: Alarm = Alarm::Policy(PolicyError::ExternalCommitContent);

    #[test]
    fn an_external_commit_carries_its_init_and_at_most_its_own_resync() {
        let joiner = device(BOB, 0xb3);
        let committer = Committer::Joiner(joiner);
        let init = by_value(Kind::ExternalInit);
        let own_resync = by_value(remove(4, joiner));

        assert_eq!(check(committer, &[init], &[]), Ok((vec![], vec![])));
        assert_eq!(
            check(committer, &[init, own_resync], &[]),
            Ok((vec![], leaves(&[4])))
        );

        // Never a removal of the server by reference, before or after the
        // resync, even of a leaf the server asked to remove.
        let server_removal = from_server(remove(3, device(ALICE, 0xa2)));
        for entries in [
            vec![init, server_removal],
            vec![init, server_removal, own_resync],
            vec![init, own_resync, server_removal],
        ] {
            assert_eq!(
                check(committer, &entries, &[3]),
                Err(EXTERNAL_COMMIT),
                "{entries:?}"
            );
        }
        // Its own earlier leaf by reference, or twice.
        for entries in [
            vec![init, by_reference(remove(4, joiner))],
            vec![init, own_resync, by_value(remove(5, joiner))],
            vec![by_reference(Kind::ExternalInit)],
        ] {
            assert_eq!(
                check(committer, &entries, &[]),
                Err(EXTERNAL_COMMIT),
                "{entries:?}"
            );
        }
        // Another device of the same user, a device of another user, an
        // empty leaf, or anything else.
        for other in [
            by_value(remove(4, device(BOB, 0xb1))),
            by_value(remove(4, device(ALICE, 0xb3))),
            by_value(Kind::Remove {
                index: LeafNodeIndex::new(4),
                device: None,
            }),
            by_value(Kind::Add(Ok(device(BOB, 0xb4)))),
            by_value(Kind::Other),
        ] {
            assert_eq!(
                check(committer, &[init, other], &[]),
                Err(EXTERNAL_COMMIT),
                "{other:?}"
            );
        }
    }

    #[test]
    fn a_member_commits_its_changes_by_value_and_the_server_s_removals_by_reference() {
        let alice1 = device(ALICE, 0xa1);
        let committer = Committer::Member(alice1);
        let bob2 = device(BOB, 0xb2);

        // Allowed: the server's removals, its own user's devices, the
        // leaves the server asked to remove, verified adds.
        let entries = [
            from_server(remove(3, bob2)),
            by_value(remove(1, device(ALICE, 0xa2))),
            by_value(remove(2, device(BOB, 0xb1))),
            by_value(Kind::Add(Ok(device(BOB, 0xb3)))),
        ];
        assert_eq!(
            check(committer, &entries, &[2, 3]),
            Ok((vec![device(BOB, 0xb3)], leaves(&[3, 1, 2])))
        );

        let refused = |entry: Entry, requested: &[u32]| {
            check(committer, &[entry], requested)
                .map(|_| ())
                .unwrap_err()
        };
        assert_eq!(
            refused(by_value(remove(2, device(BOB, 0xb1))), &[3]),
            Alarm::Policy(PolicyError::RemoveNotAllowed)
        );
        assert_eq!(
            refused(by_reference(remove(1, device(ALICE, 0xa2))), &[]),
            Alarm::Policy(PolicyError::MemberProposal)
        );
        assert_eq!(
            refused(by_reference(Kind::Add(Ok(device(BOB, 0xb3)))), &[]),
            Alarm::Policy(PolicyError::MemberProposal)
        );
        assert_eq!(
            refused(from_server(Kind::Other), &[]),
            Alarm::Policy(PolicyError::ExternalProposalNotRemove)
        );
        assert_eq!(
            refused(by_value(Kind::Add(Err(LeafError::Untrusted))), &[]),
            Alarm::Leaf(LeafError::Untrusted)
        );
        // Anything else, group context changes included (`entry` makes
        // them `Other`).
        for forbidden in [Kind::Other, Kind::ExternalInit] {
            assert_eq!(
                refused(by_value(forbidden), &[]),
                Alarm::Policy(PolicyError::ForbiddenProposal)
            );
        }
    }

    #[test]
    fn a_device_keeps_its_key_in_the_group_a_resync_included() {
        let d = device(ALICE, 0xa2);
        let before: HashMap<_, _> = [(d, vec![1; 32]), (device(BOB, 0xb1), vec![2; 32])]
            .into_iter()
            .collect();
        // The resync the review describes: the commit removes D's leaf and
        // adds D again under another key. `before` is the group before the
        // commit, so D is in it whatever the commit removes.
        assert_eq!(
            check_keys(&before, &[(d, vec![9; 32])]),
            Err(LeafError::KeyChanged)
        );
        // An honest resync keeps the key; a new device has none yet.
        assert_eq!(check_keys(&before, &[(d, vec![1; 32])]), Ok(()));
        assert_eq!(
            check_keys(&before, &[(device(ALICE, 0xa3), vec![9; 32])]),
            Ok(())
        );
    }
}
