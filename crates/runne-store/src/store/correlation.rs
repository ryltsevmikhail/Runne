use super::{CORRELATION_TYPE_CONVERSATION, CORRELATION_TYPE_TASK_RUN, EventStoreError};

#[derive(Clone, Copy)]
pub(super) enum StoredCorrelationType {
    TaskRun,
    Conversation,
}

impl StoredCorrelationType {
    pub(super) fn from_i64(value: i64) -> Result<Self, EventStoreError> {
        match value {
            CORRELATION_TYPE_TASK_RUN => Ok(Self::TaskRun),
            CORRELATION_TYPE_CONVERSATION => Ok(Self::Conversation),
            _ => Err(EventStoreError::CorruptData),
        }
    }

    pub(super) const fn as_i64(self) -> i64 {
        match self {
            Self::TaskRun => CORRELATION_TYPE_TASK_RUN,
            Self::Conversation => CORRELATION_TYPE_CONVERSATION,
        }
    }
}
