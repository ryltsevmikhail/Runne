use runne_application::ports::{
    PreparedTaskRunProviderRequest, TaskRunAssignmentIdentity, TaskRunProviderBindingError as Error,
};
use runne_provider::ProviderCallDigestVersion;
use rusqlite::{OptionalExtension, params};
use std::str::FromStr;

pub(super) type BindingRow = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
);
pub(super) type PreparedRow = (
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

pub(super) fn validate_prepared_request(
    prepared: &PreparedTaskRunProviderRequest,
) -> Result<(), Error> {
    if prepared.provider_idempotency_key.is_empty()
        || prepared.provider_idempotency_key.len() > 256
        || !prepared
            .provider_idempotency_key
            .bytes()
            .all(|b| b.is_ascii_graphic())
        || *prepared.call_id.as_bytes() == [0; 16]
    {
        return Err(Error::NotPrepared);
    }
    Ok(())
}

pub(super) fn verify_prepared_metadata(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    prepared: &PreparedTaskRunProviderRequest,
    version: i64,
) -> Result<(), Error> {
    let row: Option<PreparedRow> = tx.query_row(
        "SELECT p.call_digest_version,p.prepared_digest,p.render_digest,p.profile_digest,a.prepared_digest,a.render_digest,a.profile_digest,a.call_id,a.provider_idempotency_key,a.taskrun_id,a.execution_attempt_id,d.call_id,d.provider_idempotency_key,d.prepared_digest,d.render_digest,d.profile_digest FROM provider_prepared_requests p JOIN provider_execution_admissions a USING(call_id) JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id WHERE p.call_id=?1",
        [prepared.call_id.as_bytes()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?)),
    ).optional().map_err(|_| Error::CorruptData)?;
    let Some(row) = row else {
        return Err(Error::NotPrepared);
    };
    if row.0 != version
        || row.1.as_slice() != prepared.prepared_digest
        || row.2.as_slice() != prepared.render_digest
        || row.3.as_slice() != prepared.profile_digest
        || row.4 != row.1
        || row.5 != row.2
        || row.6 != row.3
        || row.7.as_slice() != prepared.call_id.as_bytes()
        || row.8 != prepared.provider_idempotency_key
        || row.9.as_slice() != identity.taskrun_id.as_bytes()
        || row.10.as_slice() != identity.attempt_id.as_bytes()
        || row.11.as_slice() != prepared.call_id.as_bytes()
        || row.12 != prepared.provider_idempotency_key
        || row.13.as_slice() != prepared.prepared_digest
        || row.14.as_slice() != prepared.render_digest
        || row.15.as_slice() != prepared.profile_digest
    {
        return Err(Error::IdempotencyConflict);
    }
    Ok(())
}

pub(super) fn load_binding(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
) -> Result<Option<BindingRow>, Error> {
    tx.query_row(
        "SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,claim_version,call_id,call_digest_version,prepared_digest,render_digest,profile_digest,provider_idempotency_key FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2",
        params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?)),
    ).optional().map_err(|_| Error::CorruptData)
}

pub(super) fn binding_matches(
    row: &BindingRow,
    identity: &TaskRunAssignmentIdentity,
    node: [u8; 16],
    claim_version: u64,
    prepared: &PreparedTaskRunProviderRequest,
    version: i64,
) -> bool {
    row.0.as_slice() == identity.taskrun_id.as_bytes()
        && row.1 == identity.fence.0 as i64
        && row.2.as_slice() == identity.attempt_id.as_bytes()
        && row.3 == node
        && row.4 == identity.node_epoch as i64
        && row.5 == claim_version as i64
        && row.6.as_slice() == prepared.call_id.as_bytes()
        && row.7 == version
        && row.8.as_slice() == prepared.prepared_digest
        && row.9.as_slice() == prepared.render_digest
        && row.10.as_slice() == prepared.profile_digest
        && row.11 == prepared.provider_idempotency_key
}

pub(super) fn ensure_present_intent(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    node: [u8; 16],
    now: i64,
    existing: &str,
) -> Result<(), Error> {
    if existing == "absent" {
        tx.execute("INSERT INTO taskrun_dispatch_intents(taskrun_id,fence,attempt_id,node_id,node_epoch,state) VALUES(?1,?2,?3,?4,?5,'present')",
            params![identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node,identity.node_epoch as i64]).map_err(|_| Error::CorruptData)?;
        let changed = tx.execute("UPDATE taskrun_assignment_occupations SET dispatch_intent='present' WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND state='active' AND dispatch_intent='absent' AND lease_expires_at_ms>?6",
            params![identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node,identity.node_epoch as i64,now]).map_err(|_| Error::CorruptData)?;
        if changed != 1 {
            return Err(Error::StaleAssignment);
        }
        return Ok(());
    }
    // An unbound V44 intent may represent an already prepared or uncertain
    // external dispatch. Never attach a fresh provider call to that history.
    Err(Error::StaleAssignment)
}

pub(super) fn binding_node_id(identity: &TaskRunAssignmentIdentity) -> Result<[u8; 16], Error> {
    let parsed = uuid::Uuid::from_str(&identity.node_id.0).map_err(|_| Error::StaleAssignment)?;
    if parsed.is_nil()
        || parsed.to_string() != identity.node_id.0
        || identity.node_epoch == 0
        || identity.fence.0 == 0
    {
        return Err(Error::StaleAssignment);
    }
    Ok(*parsed.as_bytes())
}

pub(super) fn digest_version_value(version: ProviderCallDigestVersion) -> i64 {
    match version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    }
}

pub(super) fn binding_now_ms(tx: &rusqlite::Transaction<'_>) -> Result<i64, Error> {
    tx.query_row(
        "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
        [],
        |r| r.get(0),
    )
    .map_err(|_| Error::Unavailable)
}

pub(super) fn map_assignment_error(
    error: runne_application::ports::TaskRunAssignmentError,
) -> Error {
    use runne_application::ports::TaskRunAssignmentError as AssignmentError;
    match error {
        AssignmentError::StaleAssignment => Error::StaleAssignment,
        AssignmentError::LeaseExpired => Error::LeaseExpired,
        AssignmentError::NodeUnavailable => Error::NodeUnavailable,
        AssignmentError::IdempotencyConflict => Error::IdempotencyConflict,
        AssignmentError::CorruptData => Error::CorruptData,
        AssignmentError::Unavailable => Error::Unavailable,
    }
}
