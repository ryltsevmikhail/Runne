use super::super::*;
use runne_application::ports::EventStoreError;
use runne_domain::id::TaskRunId;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

type ApprovalBindingRow = (
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
);

/// Durable local-command approval/launch lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalCommandAttemptState {
    Preflight,
    ApprovalPending,
    Approved,
    LaunchIntent,
    ReleaseReserved,
    Running,
    CancelRequested,
    Completed,
    Cancelled,
    Denied,
    NoEffectTerminal,
    StopUnconfirmed,
    OutcomeUnknown,
}

impl LocalCommandAttemptState {
    pub(super) const fn as_sql(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::ApprovalPending => "approval_pending",
            Self::Approved => "approved",
            Self::LaunchIntent => "launch_intent",
            Self::ReleaseReserved => "release_reserved",
            Self::Running => "running",
            Self::CancelRequested => "cancel_requested",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Denied => "denied",
            Self::NoEffectTerminal => "no_effect_terminal",
            Self::StopUnconfirmed => "stop_unconfirmed",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }

    pub(super) fn from_sql(value: &str) -> Result<Self, EventStoreError> {
        match value {
            "preflight" => Ok(Self::Preflight),
            "approval_pending" => Ok(Self::ApprovalPending),
            "approved" => Ok(Self::Approved),
            "launch_intent" => Ok(Self::LaunchIntent),
            "release_reserved" => Ok(Self::ReleaseReserved),
            "running" => Ok(Self::Running),
            "cancel_requested" => Ok(Self::CancelRequested),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            "denied" => Ok(Self::Denied),
            "no_effect_terminal" => Ok(Self::NoEffectTerminal),
            "stop_unconfirmed" => Ok(Self::StopUnconfirmed),
            "outcome_unknown" => Ok(Self::OutcomeUnknown),
            _ => Err(EventStoreError::CorruptData),
        }
    }
}

/// Exact prepared executable/root/trust/approval identity persisted before claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalCommandApprovalBinding {
    pub command_digest: [u8; 32],
    pub executable_digest: [u8; 32],
    pub workspace_version: u64,
    pub admitted_root_version: u64,
    pub admitted_root_identity: [u8; 32],
    pub trust_epoch: u64,
    pub trust_revision: u64,
    pub source_policy_version: u64,
    pub command_policy_version: u64,
    pub approval_id: [u8; 16],
}

impl StoreTransaction {
    /// Returns the principal bound to the immutable submitted TaskRun receipt.
    pub fn taskrun_submit_principal(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<Option<runne_application::ports::PrincipalId>, EventStoreError> {
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
            &connection,
            taskrun_id,
            &self.runtime_authority_id,
        )
        .map(|origin| origin.map(|value| value.principal_id))
        .map_err(|_| EventStoreError::CorruptData)
    }

    /// Reads one local-command state from the authoritative reader connection.
    pub fn local_command_attempt_state(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<Option<LocalCommandAttemptState>, EventStoreError> {
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        connection
            .query_row(
                "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?
            .as_deref()
            .map(LocalCommandAttemptState::from_sql)
            .transpose()
    }

    /// Stores preclaim approval binding once; immutable identity cannot be replaced.
    pub fn bind_local_command_approval(
        &self,
        taskrun_id: TaskRunId,
        binding: LocalCommandApprovalBinding,
        state: LocalCommandAttemptState,
    ) -> Result<(), EventStoreError> {
        if !matches!(
            state,
            LocalCommandAttemptState::ApprovalPending
                | LocalCommandAttemptState::Approved
                | LocalCommandAttemptState::Denied
        ) || binding.workspace_version == 0
            || binding.admitted_root_version == 0
            || binding.trust_epoch == 0
            || binding.trust_revision == 0
            || binding.source_policy_version != 2
            || binding.command_policy_version != 1
            || binding.approval_id == [0; 16]
        {
            return Err(EventStoreError::CorruptData);
        }
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        let current: Option<ApprovalBindingRow> = tx.query_row(
            "SELECT state,command_digest,executable_digest,workspace_version,admitted_root_version,admitted_root_identity,trust_epoch,trust_revision,source_policy_version,command_policy_version,approval_id FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)),
        ).optional().map_err(|_| EventStoreError::CorruptData)?;
        let Some(current) = current else {
            return Err(EventStoreError::CorruptData);
        };
        if current.1.as_deref() != Some(binding.command_digest.as_slice()) {
            return Err(EventStoreError::CorruptData);
        }
        let existing_bound = current.2.is_some();
        if existing_bound && !binding_matches(&current, binding) {
            return Err(EventStoreError::CorruptData);
        }
        let old_state = LocalCommandAttemptState::from_sql(&current.0)?;
        if existing_bound && old_state == state {
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        let transition_ok = matches!(
            old_state,
            LocalCommandAttemptState::Preflight
                | LocalCommandAttemptState::ApprovalPending
                | LocalCommandAttemptState::Approved
        ) && matches!(
            state,
            LocalCommandAttemptState::ApprovalPending
                | LocalCommandAttemptState::Approved
                | LocalCommandAttemptState::Denied
        );
        if !transition_ok {
            return Err(EventStoreError::CorruptData);
        }
        let workspace_version =
            i64::try_from(binding.workspace_version).map_err(|_| EventStoreError::CorruptData)?;
        let root_version = i64::try_from(binding.admitted_root_version)
            .map_err(|_| EventStoreError::CorruptData)?;
        let trust_epoch =
            i64::try_from(binding.trust_epoch).map_err(|_| EventStoreError::CorruptData)?;
        let trust_revision =
            i64::try_from(binding.trust_revision).map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET executable_digest=?1,workspace_version=?2,admitted_root_version=?3,admitted_root_identity=?4,trust_epoch=?5,trust_revision=?6,source_policy_version=?7,command_policy_version=?8,approval_id=?9,state=?10,updated_at=?11 WHERE taskrun_id=?12 AND command_digest=?13",
            params![binding.executable_digest.as_slice(),workspace_version,root_version,binding.admitted_root_identity.as_slice(),trust_epoch,trust_revision,binding.source_policy_version as i64,binding.command_policy_version as i64,binding.approval_id.as_slice(),state.as_sql(),now_millis(),taskrun_id.as_bytes(),binding.command_digest.as_slice()],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn binding_matches(current: &ApprovalBindingRow, expected: LocalCommandApprovalBinding) -> bool {
    current.1.as_deref() == Some(expected.command_digest.as_slice())
        && current.2.as_deref() == Some(expected.executable_digest.as_slice())
        && current.3 == Some(expected.workspace_version as i64)
        && current.4 == Some(expected.admitted_root_version as i64)
        && current.5.as_deref() == Some(expected.admitted_root_identity.as_slice())
        && current.6 == Some(expected.trust_epoch as i64)
        && current.7 == Some(expected.trust_revision as i64)
        && current.8 == Some(expected.source_policy_version as i64)
        && current.9 == Some(expected.command_policy_version as i64)
        && current.10.as_deref() == Some(expected.approval_id.as_slice())
}
