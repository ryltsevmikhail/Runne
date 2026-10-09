use std::time::Duration;

#[derive(Debug, PartialEq)]
pub(super) struct NativeUnknownFreshClaimSnapshot {
    pub(super) stream: Vec<Vec<rusqlite::types::Value>>,
    pub(super) event_ids: Vec<Vec<rusqlite::types::Value>>,
    pub(super) effects: runne_api::TaskRunEffectsV1,
    pub(super) local_attempts: Vec<Vec<rusqlite::types::Value>>,
    pub(super) stop_receipts: Vec<Vec<rusqlite::types::Value>>,
    pub(super) terminal_receipts: Vec<Vec<rusqlite::types::Value>>,
    pub(super) assignments: Vec<Vec<rusqlite::types::Value>>,
    pub(super) assignment_occupations: Vec<Vec<rusqlite::types::Value>>,
    pub(super) claim_receipts: Vec<Vec<rusqlite::types::Value>>,
    pub(super) lease_renewals: Vec<Vec<rusqlite::types::Value>>,
    pub(super) execution_nodes: Vec<Vec<rusqlite::types::Value>>,
    pub(super) append_bytes: Vec<Vec<rusqlite::types::Value>>,
}

pub(super) fn native_unknown_fresh_claim_snapshot(
    connection: &rusqlite::Connection,
    taskrun_id: &[u8],
    effects: runne_api::TaskRunEffectsV1,
) -> rusqlite::Result<NativeUnknownFreshClaimSnapshot> {
    Ok(NativeUnknownFreshClaimSnapshot {
        stream: native_claim_rows(
            connection,
            "SELECT * FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_id],
        )?,
        event_ids: native_claim_rows(
            connection,
            "SELECT event_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
            [taskrun_id],
        )?,
        effects,
        local_attempts: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        stop_receipts: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        terminal_receipts: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        assignments: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_assignments WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        assignment_occupations: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        claim_receipts: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_claim_receipts WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        lease_renewals: native_claim_rows(
            connection,
            "SELECT * FROM taskrun_assignment_lease_renewals WHERE taskrun_id=?1",
            [taskrun_id],
        )?,
        execution_nodes: native_claim_rows(
            connection,
            "SELECT * FROM execution_nodes ORDER BY node_id",
            rusqlite::params![],
        )?,
        append_bytes: native_claim_rows(
            connection,
            "SELECT command_id,idempotency_key,actor,payload,integrity_digest,correlation_id
             FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
            [taskrun_id],
        )?,
    })
}

fn native_claim_rows<P: rusqlite::Params>(
    connection: &rusqlite::Connection,
    sql: &str,
    parameters: P,
) -> rusqlite::Result<Vec<Vec<rusqlite::types::Value>>> {
    let mut statement = connection.prepare(sql)?;
    let column_count = statement.column_count();
    statement
        .query_map(parameters, |row| {
            (0..column_count)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?
        .collect()
}

pub(super) fn validate_native_runtime_identity(
    connection: &rusqlite::Connection,
    authority_id: [u8; 16],
    lineage_id: runne_domain::id::EventLogLineageId,
) -> rusqlite::Result<()> {
    if runne_store::schema::read_authority_id(connection)? == Some(authority_id)
        && runne_store::schema::read_event_log_lineage_id(connection)? == Some(lineage_id)
    {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

pub(super) struct FreshClaimAllowContent;

impl runne_application::prohibited_content::ProhibitedContentPort for FreshClaimAllowContent {
    fn inspect(
        &self,
        _boundary: runne_application::prohibited_content::CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<
        runne_application::prohibited_content::ContentDisposition,
        runne_application::prohibited_content::ContentGuardError,
    > {
        Ok(runne_application::prohibited_content::ContentDisposition::Allowed { policy_epoch: 0 })
    }
}

pub(super) struct FreshClaimReadOnlyPort<'a> {
    pub(super) store: &'a runne_store::store::StoreTransaction,
    pub(super) lookups: std::cell::Cell<usize>,
}

impl runne_application::ports::TaskRunClaimPort for FreshClaimReadOnlyPort<'_> {
    fn lookup_task_run_claim(
        &self,
        lookup: runne_application::ports::TaskRunClaimLookup,
    ) -> Result<
        runne_application::ports::TaskRunClaimLookupResult,
        runne_application::ports::TaskRunClaimError,
    > {
        self.lookups.set(self.lookups.get() + 1);
        runne_application::ports::TaskRunClaimPort::lookup_task_run_claim(self.store, lookup)
    }

    fn claim_task_run(
        &self,
        _request: runne_application::ports::TaskRunClaimRequest,
    ) -> Result<
        runne_application::ports::TaskRunClaimResult,
        runne_application::ports::TaskRunClaimError,
    > {
        panic!("terminal fresh-claim preflight must not reach the mutating port")
    }
}

pub(super) async fn wait_for_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "fixture marker did not appear"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
