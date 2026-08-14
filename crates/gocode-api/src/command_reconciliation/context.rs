use crate::ApiPrincipalId;
use gocode_domain::id::{CommandId, IdempotencyKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReconciliationContext {
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
    principal: ApiPrincipalId,
}

impl CommandReconciliationContext {
    #[must_use]
    pub fn new(
        command_id: CommandId,
        idempotency_key: IdempotencyKey,
        principal: ApiPrincipalId,
    ) -> Self {
        Self {
            command_id,
            idempotency_key,
            principal,
        }
    }

    #[must_use]
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    #[must_use]
    pub fn principal(&self) -> &ApiPrincipalId {
        &self.principal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationOperation {
    CreateProject,
    ArchiveProject,
    DeleteProject,
    CreateWorkspace,
    BindWorkspaceRoot,
    OpenWorkspace,
    CreateConversation,
    GenerateConversationText,
}
