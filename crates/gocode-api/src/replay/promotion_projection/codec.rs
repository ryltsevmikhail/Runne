use gocode_domain::conversation::ConversationSnapshotV1;
use gocode_domain::id::validate_uuid_v7_bytes;
use gocode_domain::task_run::TaskRunSnapshotV1;
use sha2::{Digest, Sha256};

use super::{
    CONVERSATION_TAG, ConversationPromotionMessageV1, ConversationPromotionViewV1, MAGIC,
    ReplayPromotionProjectionViewV1, TASKRUN_TAG, TaskRunPromotionViewV1, VERSION,
};
use crate::replay::{MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1, ReplayContractError};

const HEADER_BYTES: usize = 26;

pub(super) fn decode(bytes: &[u8]) -> Result<ReplayPromotionProjectionViewV1, ReplayContractError> {
    if bytes.len() > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1 || bytes.len() < HEADER_BYTES {
        return Err(ReplayContractError::InvalidProjection);
    }
    let mut input = Input::new(bytes);
    if input.array::<4>()? != MAGIC || input.byte()? != VERSION {
        return Err(ReplayContractError::InvalidProjection);
    }
    let tag = input.byte()?;
    let id = input.array::<16>()?;
    validate_uuid_v7_bytes(&id).map_err(|_| ReplayContractError::InvalidProjection)?;
    let snapshot_length = input.u32()? as usize;
    let snapshot_bytes = input.bytes(snapshot_length)?;
    let view = match tag {
        CONVERSATION_TAG => decode_conversation(id, snapshot_bytes, &mut input)?,
        TASKRUN_TAG => decode_taskrun(id, snapshot_bytes, &input)?,
        _ => return Err(ReplayContractError::InvalidProjection),
    };
    if !input.done() {
        return Err(ReplayContractError::InvalidProjection);
    }
    Ok(view)
}

fn decode_conversation(
    id: [u8; 16],
    snapshot_bytes: &[u8],
    input: &mut Input<'_>,
) -> Result<ReplayPromotionProjectionViewV1, ReplayContractError> {
    let snapshot = ConversationSnapshotV1::decode(snapshot_bytes)
        .map_err(|_| ReplayContractError::InvalidProjection)?;
    if snapshot.id().as_bytes() != &id {
        return Err(ReplayContractError::InvalidProjection);
    }
    let count = input.u32()? as usize;
    if count != snapshot.messages().len() {
        return Err(ReplayContractError::InvalidProjection);
    }
    let mut messages = Vec::with_capacity(count);
    for message in snapshot.messages() {
        let committed_at_micros = i64::from_be_bytes(input.array::<8>()?);
        if committed_at_micros <= 0 {
            return Err(ReplayContractError::InvalidProjection);
        }
        messages.push(ConversationPromotionMessageV1 {
            message_id: message.message_id,
            role: message.role,
            taskrun_id: message.taskrun_id,
            attempt_id: message.attempt_id,
            text: message.text.as_str().to_owned(),
            committed_at_micros,
        });
    }
    Ok(ReplayPromotionProjectionViewV1::Conversation(
        ConversationPromotionViewV1 {
            id: snapshot.id(),
            workspace_id: snapshot.workspace_id(),
            state: snapshot.state(),
            messages,
            active_generation: snapshot.active_generation().copied(),
            digest: digest(CONVERSATION_TAG, &id, input.all),
        },
    ))
}

fn decode_taskrun(
    id: [u8; 16],
    snapshot_bytes: &[u8],
    input: &Input<'_>,
) -> Result<ReplayPromotionProjectionViewV1, ReplayContractError> {
    let snapshot = TaskRunSnapshotV1::decode(snapshot_bytes)
        .map_err(|_| ReplayContractError::InvalidProjection)?;
    if snapshot.id().as_bytes() != &id || !input.done() {
        return Err(ReplayContractError::InvalidProjection);
    }
    Ok(ReplayPromotionProjectionViewV1::TaskRun(Box::new(
        TaskRunPromotionViewV1 {
            id: snapshot.id(),
            state: super::taskrun_map::state(&snapshot),
            digest: digest(TASKRUN_TAG, &id, input.all),
        },
    )))
}

pub(super) fn header(
    tag: u8,
    id: &[u8; 16],
    snapshot: &[u8],
) -> Result<Vec<u8>, ReplayContractError> {
    validate_uuid_v7_bytes(id).map_err(|_| ReplayContractError::InvalidProjection)?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + snapshot.len());
    push(&mut bytes, &MAGIC)?;
    push(&mut bytes, &[VERSION, tag])?;
    push(&mut bytes, id)?;
    push_u32(&mut bytes, snapshot.len())?;
    push(&mut bytes, snapshot)?;
    Ok(bytes)
}

pub(super) fn push_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), ReplayContractError> {
    push(
        bytes,
        &u32::try_from(value)
            .map_err(|_| ReplayContractError::InvalidProjection)?
            .to_be_bytes(),
    )
}

pub(super) fn push(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ReplayContractError> {
    if bytes
        .len()
        .checked_add(value.len())
        .is_none_or(|length| length > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1)
    {
        return Err(ReplayContractError::InvalidProjection);
    }
    bytes.extend_from_slice(value);
    Ok(())
}

fn digest(tag: u8, id: &[u8; 16], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode.replay.promotion-projection");
    hasher.update([0, VERSION, tag]);
    hasher.update(id);
    hasher.update(bytes);
    hasher.finalize().into()
}

struct Input<'a> {
    all: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    const fn new(all: &'a [u8]) -> Self {
        Self { all, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, ReplayContractError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, ReplayContractError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReplayContractError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| ReplayContractError::InvalidProjection)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], ReplayContractError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.all.len())
            .ok_or(ReplayContractError::InvalidProjection)?;
        let bytes = &self.all[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    const fn done(&self) -> bool {
        self.offset == self.all.len()
    }
}
