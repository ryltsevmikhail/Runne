use crate::store::{ClosedRulesManagedIdentityV2, StoreTransaction};
use runne_application::{
    ports::EventStoreError,
    project_trust::{ProjectTrustEffectLease, ProjectTrustProjectId},
};
use runne_domain::id::TaskRunId;
use rusqlite::Transaction;

pub(in crate::store) fn can_retain_in_tx(
    tx: &Transaction<'_>,
    store: &StoreTransaction,
    taskrun: TaskRunId,
    current: &ClosedRulesManagedIdentityV2,
    lease: &dyn ProjectTrustEffectLease,
) -> Result<bool, EventStoreError> {
    let (capture, original) = super::retained_policy_rows::load(tx, taskrun)?;
    let Some(original) = original else {
        return Ok(false);
    };
    let record =
        super::codec::decode(&capture.binding).map_err(|_| EventStoreError::CorruptData)?;
    if record.project_id != current.project_id || record.project_version != current.project_version
    {
        return Ok(false);
    }
    if lease.snapshot().map_err(|_| EventStoreError::Unavailable)? != current.snapshot {
        return Err(EventStoreError::CorruptData);
    }
    let workspace_version: i64 = tx
        .query_row(
            "SELECT version FROM workspaces WHERE workspace_id=?1",
            [original.selection.scope.workspace_id.as_bytes()],
            |r| r.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if u64::try_from(workspace_version).ok() != Some(record.workspace_version) {
        return Ok(false);
    }
    let assessment = super::retained_policy::assess_context(
        tx,
        store,
        &original,
        &capture,
        ProjectTrustProjectId::from_bytes(record.project_id),
        lease,
    )?;
    if assessment.stop.is_some() {
        return Ok(false);
    }
    Ok(true)
}
