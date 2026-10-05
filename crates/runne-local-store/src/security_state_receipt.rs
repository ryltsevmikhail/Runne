use crate::{MutationIdentity, MutationOperation, MutationRecord};

impl MutationIdentity {
    #[must_use]
    pub const fn runtime_identity_digest(&self) -> [u8; 32] {
        self.runtime_authority_digest
    }

    #[must_use]
    pub const fn principal_digest(&self) -> [u8; 32] {
        self.principal_digest
    }

    #[must_use]
    pub const fn operation_kind(&self) -> MutationOperation {
        self.operation
    }

    #[must_use]
    pub const fn stored_target(&self) -> &crate::StoredMutationTarget {
        &self.target
    }
}

impl MutationRecord {
    #[must_use]
    pub const fn identity(&self) -> &MutationIdentity {
        &self.identity
    }
}
