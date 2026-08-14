use super::{ActiveTextGeneration, ConversationMessage, ConversationSnapshotV1, ConversationState, WorkspaceId};

impl ConversationSnapshotV1 {
    /// Returns the workspace owning this immutable snapshot.
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the closed lifecycle state.
    pub const fn state(&self) -> ConversationState {
        self.state
    }

    /// Returns the validated message timeline in canonical order.
    pub fn messages(&self) -> &[ConversationMessage] {
        &self.messages
    }

    /// Returns the active generation binding, if a response is pending.
    pub const fn active_generation(&self) -> Option<&ActiveTextGeneration> {
        self.active_generation.as_ref()
    }
}
