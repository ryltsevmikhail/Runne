//! Conversation aggregate — session lifecycle state machine.

use crate::event::{DomainEventDraft, EventEnvelope, Sensitivity};
use crate::id::{AggregateId, AttemptId, ConversationId, MessageId, TaskRunId, WorkspaceId};
use crate::message::{ConversationMessage, MessageRole, MessageText};

pub use crate::command::ConversationCommand;

include!("conversation/types.rs");
include!("conversation/aggregate.rs");
include!("conversation/invariants.rs");
include!("conversation/snapshot.rs");

#[cfg(test)]
mod tests {
    include!("conversation/tests/setup.rs");
    include!("conversation/tests/lifecycle.rs");
    include!("conversation/tests/validation.rs");
}
