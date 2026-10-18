use super::AdminError;
use super::ReservedManagedPolicyCommandV1;
use std::fmt;

/// Durable administrator registry state read under the same T1 writer fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedPolicyRoleState {
    /// The singleton protected administrator is active at `generation`.
    Active { generation: u64 },
    /// The role was explicitly revoked and cannot be restored by registration retry.
    Revoked { generation: u64 },
}

/// Distinct durable terminal states for one exact command identity.
#[derive(PartialEq, Eq)]
pub enum ManagedPolicyCommandState {
    /// Command is pending native consent until its finite expiry.
    Pending(ReservedManagedPolicyCommandV1),
    /// Command committed and has this immutable receipt.
    Committed(ManagedPolicyAdminReceipt),
    /// Pending command was explicitly cancelled.
    Cancelled,
    /// Pending command expired before commit.
    Expired,
    /// Pending command was invalidated by another policy or role change.
    Invalidated,
}

impl fmt::Debug for ManagedPolicyCommandState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending(_) => f.write_str("Pending(<challenge redacted>)"),
            Self::Committed(receipt) => f.debug_tuple("Committed").field(receipt).finish(),
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Expired => f.write_str("Expired"),
            Self::Invalidated => f.write_str("Invalidated"),
        }
    }
}

/// Immutable persisted receipt for one managed six-rule policy revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPolicyAdminReceipt {
    command_id: [u8; 16],
    idempotency_key: String,
    stable_subject_digest: [u8; 32],
    authority_id: [u8; 16],
    lineage_id: [u8; 16],
    project_id: [u8; 16],
    instance_epoch: u64,
    prior_revision: u64,
    revision: u64,
    old_rules_digest: [u8; 32],
    new_rules_digest: [u8; 32],
    command_digest: [u8; 32],
    committed_at_unix_ms: i64,
}

impl ManagedPolicyAdminReceipt {
    /// Constructs the read-only DTO decoded from an authenticated store row.
    ///
    /// The constructor does not create a durable receipt and its value grants
    /// no authority. Only a committed row can be returned by Store readback.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted(
        command_id: [u8; 16],
        idempotency_key: String,
        stable_subject_digest: [u8; 32],
        authority_id: [u8; 16],
        lineage_id: [u8; 16],
        project_id: [u8; 16],
        instance_epoch: u64,
        prior_revision: u64,
        revision: u64,
        old_rules_digest: [u8; 32],
        new_rules_digest: [u8; 32],
        command_digest: [u8; 32],
        committed_at_unix_ms: i64,
    ) -> Result<Self, AdminError> {
        let next_revision = prior_revision
            .checked_add(1)
            .ok_or(AdminError::Unavailable)?;
        if command_id == [0; 16]
            || idempotency_key.is_empty()
            || idempotency_key.len() > 256
            || stable_subject_digest == [0; 32]
            || authority_id == [0; 16]
            || lineage_id == [0; 16]
            || project_id == [0; 16]
            || instance_epoch == 0
            || prior_revision == 0
            || revision != next_revision
            || old_rules_digest == [0; 32]
            || new_rules_digest == [0; 32]
            || command_digest == [0; 32]
            || committed_at_unix_ms <= 0
        {
            return Err(AdminError::Unavailable);
        }
        Ok(Self {
            command_id,
            idempotency_key,
            stable_subject_digest,
            authority_id,
            lineage_id,
            project_id,
            instance_epoch,
            prior_revision,
            revision,
            old_rules_digest,
            new_rules_digest,
            command_digest,
            committed_at_unix_ms,
        })
    }

    pub const fn command_id(&self) -> &[u8; 16] {
        &self.command_id
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub const fn stable_subject_digest(&self) -> &[u8; 32] {
        &self.stable_subject_digest
    }
    pub const fn authority_id(&self) -> &[u8; 16] {
        &self.authority_id
    }
    pub const fn lineage_id(&self) -> &[u8; 16] {
        &self.lineage_id
    }
    pub const fn project_id(&self) -> &[u8; 16] {
        &self.project_id
    }
    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch
    }
    pub const fn prior_revision(&self) -> u64 {
        self.prior_revision
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn old_rules_digest(&self) -> &[u8; 32] {
        &self.old_rules_digest
    }
    pub const fn new_rules_digest(&self) -> &[u8; 32] {
        &self.new_rules_digest
    }
    pub const fn command_digest(&self) -> &[u8; 32] {
        &self.command_digest
    }
    pub const fn committed_at_unix_ms(&self) -> i64 {
        self.committed_at_unix_ms
    }
}
