// SPDX-License-Identifier: AGPL-3.0-or-later

//! MLS group ids: the conversation id followed by the group generation, a
//! 32-bit big-endian counter that starts at 0 and grows each time the
//! conversation's group is recreated (ADR 0019, section 17).

use openmls::prelude::GroupId;

use super::MlsError;
use crate::identity::ID_LEN;

/// Length of a group id, in bytes.
pub const LEN: usize = ID_LEN + 4;

/// Which group of which conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupIdentity {
    /// The conversation (a UUID).
    pub conversation_id: [u8; ID_LEN],
    /// How many times its group was recreated.
    pub generation: u32,
}

impl GroupIdentity {
    /// The MLS group id.
    pub fn to_group_id(&self) -> GroupId {
        let mut bytes = Vec::with_capacity(LEN);
        bytes.extend_from_slice(&self.conversation_id);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        GroupId::from_slice(&bytes)
    }

    /// Reads an MLS group id. Anything but 20 bytes is not a Tavern group.
    pub fn from_group_id(group_id: &GroupId) -> Result<Self, MlsError> {
        let bytes = group_id.as_slice();
        if bytes.len() != LEN {
            return Err(MlsError::Parameters);
        }
        let (conversation, generation) = bytes.split_at(ID_LEN);
        Ok(Self {
            conversation_id: conversation.try_into().map_err(|_| MlsError::Parameters)?,
            generation: u32::from_be_bytes(
                generation.try_into().map_err(|_| MlsError::Parameters)?,
            ),
        })
    }

    /// The group that replaces this one.
    pub fn next(&self) -> Option<Self> {
        Some(Self {
            conversation_id: self.conversation_id,
            generation: self.generation.checked_add(1)?,
        })
    }
}
