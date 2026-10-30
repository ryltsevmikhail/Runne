use super::*;
use runne_application::ports::{
    TaskRunAssignmentError as Error, TaskRunAssignmentIdentity as Identity, TaskRunAssignmentPort,
    TaskRunDispatchIntentResult, TaskRunLeaseReceipt, TaskRunLeaseRenewal,
};
use rusqlite::TransactionBehavior;
use std::str::FromStr;

const MAX_LEASE_MS: u64 = 300_000;
type Occupation = (Vec<u8>, Vec<u8>, i64, i64, String, String);
type RenewalRow = (Vec<u8>, i64, i64, Vec<u8>, Vec<u8>, i64, i64);
type NodeRow = (i64, i64, String, String, String, i64, i64, i64);

impl TaskRunAssignmentPort for StoreTransaction {
    fn prepare_taskrun_dispatch(
        &self,
        identity: Identity,
    ) -> Result<TaskRunDispatchIntentResult, Error> {
        let node = validate_node_id(&identity)?;
        let mut writer = self.inner.writer.lock().map_err(|_| Error::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        let now = now_ms(&tx)?;
        let row = exact_occupation(&tx, &identity, node)?;
        verify_current_claim(&tx, &identity)?;
        ensure_live_local_node(&tx, &identity, node, now)?;
        if row.3 <= now {
            return Err(Error::LeaseExpired);
        }
        if row.4 != "active" {
            return Err(Error::StaleAssignment);
        }
        match row.5.as_str() {
            "present" => {
                let matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND state='present')", params![identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node,identity.node_epoch as i64], |r| r.get(0)).map_err(|_| Error::CorruptData)?;
                if !matches {
                    return Err(Error::CorruptData);
                }
                tx.commit().map_err(|_| Error::Unavailable)?;
                Ok(TaskRunDispatchIntentResult::Duplicate)
            }
            "absent" => {
                tx.execute("INSERT INTO taskrun_dispatch_intents(taskrun_id,fence,attempt_id,node_id,node_epoch,state) VALUES(?1,?2,?3,?4,?5,'present')",
                    params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64, identity.attempt_id.as_bytes(), node, identity.node_epoch as i64]).map_err(|_| Error::CorruptData)?;
                let changed = tx.execute("UPDATE taskrun_assignment_occupations SET dispatch_intent='present' WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND state='active' AND dispatch_intent='absent' AND lease_expires_at_ms>?6",
                    params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64, identity.attempt_id.as_bytes(), node, identity.node_epoch as i64, now]).map_err(|_| Error::CorruptData)?;
                if changed != 1 {
                    return Err(Error::StaleAssignment);
                }
                tx.commit().map_err(|_| Error::Unavailable)?;
                Ok(TaskRunDispatchIntentResult::Prepared)
            }
            "unknown" => Err(Error::StaleAssignment),
            _ => Err(Error::CorruptData),
        }
    }

    fn renew_taskrun_assignment_lease(
        &self,
        request: TaskRunLeaseRenewal,
    ) -> Result<TaskRunLeaseReceipt, Error> {
        let identity = &request.identity;
        let node = validate_node_id(identity)?;
        if request.lease_duration_ms == 0 || request.lease_duration_ms > MAX_LEASE_MS {
            return Err(Error::StaleAssignment);
        }
        let duration =
            i64::try_from(request.lease_duration_ms).map_err(|_| Error::StaleAssignment)?;
        let mut writer = self.inner.writer.lock().map_err(|_| Error::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        let duplicate: Option<RenewalRow> = tx.query_row(
            "SELECT taskrun_id,fence,node_epoch,attempt_id,node_id,lease_duration_ms,lease_expires_at_ms FROM taskrun_assignment_lease_renewals WHERE renewal_id=?1",
            [request.renewal_id.as_bytes()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(|_| Error::CorruptData)?;
        if let Some((taskrun, fence, epoch, attempt, stored_node, stored_duration, expiry)) =
            duplicate
        {
            if taskrun.as_slice() != identity.taskrun_id.as_bytes()
                || fence != identity.fence.0 as i64
                || epoch != identity.node_epoch as i64
                || attempt.as_slice() != identity.attempt_id.as_bytes()
                || stored_node != node
                || stored_duration != duration
            {
                return Err(Error::IdempotencyConflict);
            }
            let now = now_ms(&tx)?;
            let current = exact_occupation(&tx, identity, node)?;
            verify_current_claim(&tx, identity)?;
            ensure_live_local_node(&tx, identity, node, now)?;
            if current.3 <= now {
                return Err(Error::LeaseExpired);
            }
            if current.4 != "active"
                || !matches!(current.5.as_str(), "absent" | "present")
                || expiry > current.3
            {
                return Err(Error::StaleAssignment);
            }
            tx.commit().map_err(|_| Error::Unavailable)?;
            return lease_receipt(expiry);
        }
        if renewal_id_in_use(&tx, request.renewal_id)? {
            return Err(Error::IdempotencyConflict);
        }
        let now = now_ms(&tx)?;
        let row = exact_occupation(&tx, identity, node)?;
        verify_current_claim(&tx, identity)?;
        ensure_live_local_node(&tx, identity, node, now)?;
        if row.3 <= now {
            return Err(Error::LeaseExpired);
        }
        if row.4 != "active" || row.5 == "unknown" {
            return Err(Error::StaleAssignment);
        }
        if row.5 != "absent" && row.5 != "present" {
            return Err(Error::CorruptData);
        }
        let requested_expiry = now.checked_add(duration).ok_or(Error::CorruptData)?;
        let expiry = requested_expiry.max(row.3);
        let changed = tx.execute("UPDATE taskrun_assignment_occupations SET lease_expires_at_ms=?1 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6 AND state='active' AND dispatch_intent IN ('absent','present') AND lease_expires_at_ms>?7",
            params![expiry,identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node,identity.node_epoch as i64,now]).map_err(|_| Error::CorruptData)?;
        if changed != 1 {
            return Err(Error::StaleAssignment);
        }
        tx.execute("INSERT INTO taskrun_assignment_lease_renewals(renewal_id,taskrun_id,fence,attempt_id,node_id,node_epoch,lease_duration_ms,lease_expires_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![request.renewal_id.as_bytes(),identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node,identity.node_epoch as i64,duration,expiry]).map_err(|_| Error::CorruptData)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        lease_receipt(expiry)
    }
}

fn renewal_id_in_use(
    tx: &rusqlite::Transaction<'_>,
    renewal_id: runne_domain::id::CommandId,
) -> Result<bool, Error> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM command_receipts WHERE command_id=?1) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=?1) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=?1)",
        [renewal_id.as_bytes()],
        |row| row.get(0),
    ).map_err(|_| Error::CorruptData)
}

pub(super) fn verify_current_claim(
    tx: &rusqlite::Transaction<'_>,
    identity: &Identity,
) -> Result<(), Error> {
    match super::taskrun_claim::verify_active_assignment(tx, identity) {
        Ok(()) => Ok(()),
        Err(runne_application::ports::TaskRunClaimError::NotQueued) => Err(Error::StaleAssignment),
        Err(_) => Err(Error::CorruptData),
    }
}

pub(super) fn exact_occupation(
    tx: &rusqlite::Transaction<'_>,
    id: &Identity,
    node: [u8; 16],
) -> Result<Occupation, Error> {
    let row: Option<Occupation> = tx.query_row("SELECT o.attempt_id,o.node_id,o.node_epoch,o.lease_expires_at_ms,o.state,o.dispatch_intent FROM taskrun_assignment_occupations o JOIN taskrun_assignments a USING(taskrun_id,fence) WHERE o.taskrun_id=?1 AND o.fence=?2 AND a.taskrun_id=o.taskrun_id AND a.fence=o.fence AND a.attempt_id=o.attempt_id AND a.node_id=o.node_id AND a.node_epoch=o.node_epoch",
        params![id.taskrun_id.as_bytes(),id.fence.0 as i64], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|_| Error::CorruptData)?;
    let Some(row) = row else {
        return Err(Error::StaleAssignment);
    };
    if row.0.as_slice() != id.attempt_id.as_bytes()
        || row.1 != node
        || row.2 != id.node_epoch as i64
    {
        return Err(Error::StaleAssignment);
    }
    Ok(row)
}

pub(super) fn ensure_live_local_node(
    tx: &rusqlite::Transaction<'_>,
    id: &Identity,
    node: [u8; 16],
    now: i64,
) -> Result<(), Error> {
    let authority: Option<Vec<u8>> = tx
        .query_row("SELECT authority_id FROM _authority WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|_| Error::CorruptData)?;
    let generation: Option<String> = tx
        .query_row(
            "SELECT value FROM _daemon_info WHERE key='launch_generation'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| Error::CorruptData)?;
    let Some(authority) = authority else {
        return Err(Error::CorruptData);
    };
    let generation = generation
        .ok_or(Error::CorruptData)?
        .parse::<u64>()
        .map_err(|_| Error::CorruptData)?;
    if authority.as_slice() != node || generation != id.node_epoch {
        return Err(Error::NodeUnavailable);
    }
    let registration: Option<NodeRow> = tx
        .query_row(
            "SELECT launch_generation,descriptor_version,platform,executor_protocol,workspace_backend,capacity,heartbeat_at_ms,expires_at_ms FROM execution_nodes WHERE node_id=?1 AND launch_generation=?2",
            params![node, id.node_epoch as i64],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
        )
        .optional()
        .map_err(|_| Error::CorruptData)?;
    let Some((epoch, descriptor, platform, protocol, workspace, capacity, heartbeat, expiry)) =
        registration
    else {
        return Err(Error::NodeUnavailable);
    };
    if epoch != id.node_epoch as i64
        || descriptor != 1
        || platform != current_node_platform()
        || protocol != "runne-taskrun-v1"
        || workspace != "git-worktree-v1"
        || capacity <= 0
        || heartbeat <= 0
        || heartbeat > now
        || expiry <= now
        || expiry <= heartbeat
        || expiry - heartbeat > 300_000
    {
        return Err(Error::NodeUnavailable);
    }
    Ok(())
}

fn validate_node_id(id: &Identity) -> Result<[u8; 16], Error> {
    let parsed = uuid::Uuid::from_str(&id.node_id.0).map_err(|_| Error::StaleAssignment)?;
    if parsed.is_nil()
        || parsed.to_string() != id.node_id.0
        || id.node_epoch == 0
        || id.fence.0 == 0
    {
        return Err(Error::StaleAssignment);
    }
    Ok(*parsed.as_bytes())
}

pub(super) fn now_ms(tx: &rusqlite::Transaction<'_>) -> Result<i64, Error> {
    tx.query_row(
        "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
        [],
        |r| r.get(0),
    )
    .map_err(|_| Error::Unavailable)
}

fn lease_receipt(expiry: i64) -> Result<TaskRunLeaseReceipt, Error> {
    let micros = expiry.checked_mul(1000).ok_or(Error::CorruptData)?;
    Ok(TaskRunLeaseReceipt {
        lease_expires_at: Timestamp::from_unix_micros(micros),
    })
}

/// Platform recorded by the local execution node.
const fn current_node_platform() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "macos")]
    {
        "darwin"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "unsupported"
    }
}
