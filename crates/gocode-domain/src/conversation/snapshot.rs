use crate::id::validate_uuid_v7_bytes;
use std::fmt;

const SNAPSHOT_VERSION: u8 = 1;
/// Maximum closed replay-baseline projection payload size.
pub const MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1: usize = 512 * 1024;

/// Complete immutable projection of a Conversation aggregate.
///
/// Fields are intentionally private: callers can inspect a replayed aggregate
/// but cannot fabricate one by constructing a projection directly.
#[derive(Clone, PartialEq, Eq)]
pub struct ConversationSnapshotV1 {
    id: ConversationId,
    workspace_id: WorkspaceId,
    state: ConversationState,
    messages: Vec<ConversationMessage>,
    active_generation: Option<ActiveTextGeneration>,
}

impl fmt::Debug for ConversationSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationSnapshotV1")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("redacted", &true)
            .finish()
    }
}

/// Closed snapshot decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationSnapshotError {
    InvalidEncoding,
    InvalidState,
}

impl ConversationSnapshotV1 {
    /// Returns the aggregate identity.
    pub const fn id(&self) -> ConversationId {
        self.id
    }

    /// Encodes one complete closed projection with no event-history fallback.
    pub fn encode(&self) -> Result<Vec<u8>, ConversationSnapshotError> {
        validate_snapshot(self)?;
        let mut out = SnapshotOutput::default();
        out.push(SNAPSHOT_VERSION);
        out.id(self.id.as_bytes());
        out.id(self.workspace_id.as_bytes());
        out.push(match self.state {
            ConversationState::Active => 1,
            ConversationState::Closed => 2,
        });
        let message_count = u32::try_from(self.messages.len())
            .map_err(|_| ConversationSnapshotError::InvalidEncoding)?;
        out.extend(&message_count.to_be_bytes());
        for message in &self.messages {
            out.id(message.message_id.as_bytes());
            out.push(match message.role {
                MessageRole::User => 1,
                MessageRole::Assistant => 2,
            });
            out.id(message.taskrun_id.as_bytes());
            out.id(message.attempt_id.as_bytes());
            let text = message.text.as_str().as_bytes();
            let text_length = u32::try_from(text.len())
                .map_err(|_| ConversationSnapshotError::InvalidEncoding)?;
            out.extend(&text_length.to_be_bytes());
            out.extend(text);
        }
        match self.active_generation {
            None => out.push(0),
            Some(active) => {
                out.push(1);
                out.id(active.user_message_id.as_bytes());
                out.id(active.taskrun_id.as_bytes());
                out.id(active.attempt_id.as_bytes());
            }
        }
        out.finish()
    }

    /// Decodes and validates one exact closed projection.
    pub fn decode(bytes: &[u8]) -> Result<Self, ConversationSnapshotError> {
        if bytes.len() > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1 {
            return Err(ConversationSnapshotError::InvalidEncoding);
        }
        let mut input = SnapshotInput { bytes, offset: 0 };
        if input.byte()? != SNAPSHOT_VERSION {
            return Err(ConversationSnapshotError::InvalidEncoding);
        }
        let id = ConversationId::from_bytes(input.uuid()?);
        let workspace_id = WorkspaceId::from_bytes(input.uuid()?);
        let state = match input.byte()? {
            1 => ConversationState::Active,
            2 => ConversationState::Closed,
            _ => return Err(ConversationSnapshotError::InvalidEncoding),
        };
        let count = usize::try_from(input.u32()?)
            .map_err(|_| ConversationSnapshotError::InvalidEncoding)?;
        if count > 65_536 {
            return Err(ConversationSnapshotError::InvalidEncoding);
        }
        let mut messages = Vec::with_capacity(count);
        for _ in 0..count {
            let message_id = MessageId::from_bytes(input.uuid()?);
            let role = match input.byte()? {
                1 => MessageRole::User,
                2 => MessageRole::Assistant,
                _ => return Err(ConversationSnapshotError::InvalidEncoding),
            };
            let taskrun_id = TaskRunId::from_bytes(input.uuid()?);
            let attempt_id = AttemptId::from_bytes(input.uuid()?);
            let text = MessageText::new(
                String::from_utf8(input.bytes()?.to_vec())
                    .map_err(|_| ConversationSnapshotError::InvalidEncoding)?,
            )
            .map_err(|_| ConversationSnapshotError::InvalidEncoding)?;
            messages.push(ConversationMessage {
                message_id,
                role,
                taskrun_id,
                attempt_id,
                text,
            });
        }
        let active_generation = match input.byte()? {
            0 => None,
            1 => Some(ActiveTextGeneration {
                user_message_id: MessageId::from_bytes(input.uuid()?),
                taskrun_id: TaskRunId::from_bytes(input.uuid()?),
                attempt_id: AttemptId::from_bytes(input.uuid()?),
            }),
            _ => return Err(ConversationSnapshotError::InvalidEncoding),
        };
        if !input.done() {
            return Err(ConversationSnapshotError::InvalidEncoding);
        }
        let snapshot = Self {
            id,
            workspace_id,
            state,
            messages,
            active_generation,
        };
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }
}

#[path = "snapshot/view.rs"]
mod view;

impl Conversation {
    /// Returns a complete immutable state projection suitable for a durable baseline.
    #[must_use]
    pub fn snapshot_v1(&self) -> ConversationSnapshotV1 {
        ConversationSnapshotV1 {
            id: self.id,
            workspace_id: self.workspace_id,
            state: self.state,
            messages: self.messages.clone(),
            active_generation: self.active_generation,
        }
    }

}

fn validate_snapshot(snapshot: &ConversationSnapshotV1) -> Result<(), ConversationSnapshotError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut prior_user = None;
    for message in &snapshot.messages {
        if !seen.insert(message.message_id) {
            return Err(ConversationSnapshotError::InvalidState);
        }
        match message.role {
            MessageRole::User => {
                prior_user = Some(ActiveTextGeneration {
                    user_message_id: message.message_id,
                    taskrun_id: message.taskrun_id,
                    attempt_id: message.attempt_id,
                })
            }
            MessageRole::Assistant
                if prior_user.as_ref().is_some_and(|user| {
                    user.taskrun_id == message.taskrun_id && user.attempt_id == message.attempt_id
                }) =>
            {
                prior_user = None
            }
            _ => return Err(ConversationSnapshotError::InvalidState),
        }
    }
    if snapshot.active_generation.is_some() && snapshot.active_generation != prior_user {
        return Err(ConversationSnapshotError::InvalidState);
    }
    Ok(())
}

#[derive(Default)]
struct SnapshotOutput {
    bytes: Vec<u8>,
    invalid: bool,
}
impl SnapshotOutput {
    fn push(&mut self, value: u8) {
        self.extend(&[value]);
    }
    fn id(&mut self, value: &[u8; 16]) {
        if validate_uuid_v7_bytes(value).is_err() {
            self.invalid = true;
        } else {
            self.extend(value);
        }
    }
    fn extend(&mut self, value: &[u8]) {
        if self.invalid
            || self
                .bytes
                .len()
                .checked_add(value.len())
                .is_none_or(|length| length > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1)
        {
            self.invalid = true;
        } else {
            self.bytes.extend_from_slice(value);
        }
    }
    fn finish(self) -> Result<Vec<u8>, ConversationSnapshotError> {
        if self.invalid {
            Err(ConversationSnapshotError::InvalidEncoding)
        } else {
            Ok(self.bytes)
        }
    }
}

struct SnapshotInput<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotInput<'a> {
    fn byte(&mut self) -> Result<u8, ConversationSnapshotError> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or(ConversationSnapshotError::InvalidEncoding)?;
        self.offset += 1;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, ConversationSnapshotError> {
        Ok(u32::from_be_bytes(
            self.take_n(4)?
                .try_into()
                .map_err(|_| ConversationSnapshotError::InvalidEncoding)?,
        ))
    }
    fn uuid(&mut self) -> Result<[u8; 16], ConversationSnapshotError> {
        let value: [u8; 16] = self
            .take_n(16)?
            .try_into()
            .map_err(|_| ConversationSnapshotError::InvalidEncoding)?;
        validate_uuid_v7_bytes(&value).map_err(|_| ConversationSnapshotError::InvalidEncoding)?;
        Ok(value)
    }
    fn bytes(&mut self) -> Result<&'a [u8], ConversationSnapshotError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| ConversationSnapshotError::InvalidEncoding)?;
        if length > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1 {
            return Err(ConversationSnapshotError::InvalidEncoding);
        }
        self.take_n(length)
    }
    fn take_n(&mut self, length: usize) -> Result<&'a [u8], ConversationSnapshotError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ConversationSnapshotError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ConversationSnapshotError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
