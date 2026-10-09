pub(super) fn current_execution_node(database: &std::path::Path) -> ([u8; 16], u64) {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open execution-node reader");
    let (node_id_bytes, node_epoch): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT node_id,launch_generation FROM execution_nodes ORDER BY node_id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read the current execution node");
    (
        node_id_bytes.try_into().expect("node UUID bytes"),
        u64::try_from(node_epoch).expect("current node epoch is positive"),
    )
}

/// Snapshot every user table as sorted rendered rows so two snapshots compare
/// equal only when the whole durable database is unchanged.
pub(super) fn full_database_snapshot(database: &std::path::Path) -> Vec<(String, Vec<String>)> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open full-database snapshot reader");
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .expect("prepare table inventory")
        .query_map([], |row| row.get(0))
        .expect("read table inventory")
        .collect::<rusqlite::Result<_>>()
        .expect("collect table inventory");
    tables
        .into_iter()
        .map(|table| {
            let mut rows: Vec<String> =
                snapshot_rows(&connection, &format!("SELECT * FROM \"{table}\""))
                    .into_iter()
                    .map(|row| format!("{row:?}"))
                    .collect();
            rows.sort();
            (table, rows)
        })
        .collect()
}

fn snapshot_rows(connection: &rusqlite::Connection, sql: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let mut statement = connection.prepare(sql).expect("prepare snapshot query");
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .expect("run snapshot query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect snapshot rows")
}

pub(super) fn validate_runtime_identity(
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

pub(super) struct AllowContent;

impl runne_application::prohibited_content::ProhibitedContentPort for AllowContent {
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

pub(super) struct ReadOnlyClaimPort<'a> {
    pub(super) store: &'a runne_store::store::StoreTransaction,
    pub(super) lookups: std::cell::Cell<usize>,
}

impl runne_application::ports::TaskRunClaimPort for ReadOnlyClaimPort<'_> {
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
        panic!("the rejected new-ID claim must never reach the mutating port")
    }
}
