use rusqlite::{Connection, OptionalExtension};

use crate::QualificationReplayLedgerError;

pub fn replay_associations_are_exact(
    connection: &Connection,
    include_runs: bool,
    include_arms: bool,
) -> Result<bool, QualificationReplayLedgerError> {
    let incomplete: Option<i64> = connection.query_row(
        "SELECT 1 FROM fault_cases f LEFT JOIN replay_keys c ON c.domain=1 AND c.replay_key=f.context_id AND c.source_revision=f.source_revision AND c.workflow_run_id=f.workflow_run_id AND c.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys n ON n.domain=2 AND n.replay_key=f.context_nonce AND n.source_revision=f.source_revision AND n.workflow_run_id=f.workflow_run_id AND n.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys t ON t.domain=3 AND t.replay_key=f.ticket_id AND t.source_revision=f.source_revision AND t.workflow_run_id=f.workflow_run_id AND t.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys u ON u.domain=4 AND u.replay_key=f.ticket_nonce AND u.source_revision=f.source_revision AND u.workflow_run_id=f.workflow_run_id AND u.namespace_sha256=f.namespace_sha256 WHERE c.replay_key IS NULL OR n.replay_key IS NULL OR t.replay_key IS NULL OR u.replay_key IS NULL LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    let mut dangling_sql = String::from(
        "SELECT 1 FROM replay_keys r WHERE NOT EXISTS (SELECT 1 FROM fault_cases f WHERE r.source_revision=f.source_revision AND r.workflow_run_id=f.workflow_run_id AND r.namespace_sha256=f.namespace_sha256 AND ((r.domain=1 AND r.replay_key=f.context_id) OR (r.domain=2 AND r.replay_key=f.context_nonce) OR (r.domain=3 AND r.replay_key=f.ticket_id) OR (r.domain=4 AND r.replay_key=f.ticket_nonce)))",
    );
    if include_runs {
        dangling_sql.push_str(" AND NOT EXISTS (SELECT 1 FROM run_bootstraps b WHERE r.source_revision=b.source_revision AND r.workflow_run_id=b.workflow_run_id AND r.namespace_sha256=b.namespace_sha256 AND ((r.domain=1 AND r.replay_key=b.context_id) OR (r.domain=2 AND r.replay_key=b.context_nonce)))");
        let missing: Option<i64> = connection.query_row(
            "SELECT 1 FROM run_bootstraps b LEFT JOIN replay_keys c ON c.domain=1 AND c.replay_key=b.context_id AND c.source_revision=b.source_revision AND c.workflow_run_id=b.workflow_run_id AND c.namespace_sha256=b.namespace_sha256 LEFT JOIN replay_keys n ON n.domain=2 AND n.replay_key=b.context_nonce AND n.source_revision=b.source_revision AND n.workflow_run_id=b.workflow_run_id AND n.namespace_sha256=b.namespace_sha256 WHERE c.replay_key IS NULL OR n.replay_key IS NULL LIMIT 1", [], |row| row.get(0),
        ).optional().map_err(|_| QualificationReplayLedgerError)?;
        if missing.is_some() {
            return Ok(false);
        }
    }
    dangling_sql.push_str(" LIMIT 1");
    let dangling: Option<i64> = connection
        .query_row(&dangling_sql, [], |row| row.get(0))
        .optional()
        .map_err(|_| QualificationReplayLedgerError)?;
    let mut owners_sql = String::from(
        "SELECT 1 FROM replay_keys r WHERE ((SELECT COUNT(*) FROM fault_cases f WHERE r.source_revision=f.source_revision AND r.workflow_run_id=f.workflow_run_id AND r.namespace_sha256=f.namespace_sha256 AND ((r.domain=1 AND r.replay_key=f.context_id) OR (r.domain=2 AND r.replay_key=f.context_nonce) OR (r.domain=3 AND r.replay_key=f.ticket_id) OR (r.domain=4 AND r.replay_key=f.ticket_nonce)))",
    );
    if include_runs {
        owners_sql.push_str(" + (SELECT COUNT(*) FROM run_bootstraps b WHERE r.source_revision=b.source_revision AND r.workflow_run_id=b.workflow_run_id AND r.namespace_sha256=b.namespace_sha256 AND ((r.domain=1 AND r.replay_key=b.context_id) OR (r.domain=2 AND r.replay_key=b.context_nonce)))");
    }
    owners_sql.push_str(") != 1 LIMIT 1");
    let shared: Option<i64> = connection
        .query_row(&owners_sql, [], |row| row.get(0))
        .optional()
        .map_err(|_| QualificationReplayLedgerError)?;
    let mut orphan_sql = String::from(
        "SELECT 1 FROM immutable_runs r WHERE NOT EXISTS (SELECT 1 FROM fault_cases f WHERE r.source_revision=f.source_revision AND r.workflow_run_id=f.workflow_run_id AND r.namespace_sha256=f.namespace_sha256)",
    );
    if include_runs {
        orphan_sql.push_str(" AND NOT EXISTS (SELECT 1 FROM run_bootstraps b WHERE r.source_revision=b.source_revision AND r.workflow_run_id=b.workflow_run_id AND r.namespace_sha256=b.namespace_sha256)");
    }
    if include_arms {
        orphan_sql.push_str(" AND NOT EXISTS (SELECT 1 FROM bootstrap_arms b WHERE r.source_revision=b.source_revision AND r.workflow_run_id=b.workflow_run_id AND r.namespace_sha256=b.namespace_sha256)");
    }
    orphan_sql.push_str(" LIMIT 1");
    let orphan: Option<i64> = connection
        .query_row(&orphan_sql, [], |row| row.get(0))
        .optional()
        .map_err(|_| QualificationReplayLedgerError)?;
    Ok(incomplete.is_none() && dangling.is_none() && shared.is_none() && orphan.is_none())
}

pub fn bootstrap_arms_are_exact(
    connection: &Connection,
) -> Result<bool, QualificationReplayLedgerError> {
    let invalid: Option<i64> = connection.query_row(
        "SELECT 1 FROM bootstrap_arms WHERE length(workflow_run_id) NOT BETWEEN 1 AND 128 OR workflow_run_id GLOB '*[^0-9A-Za-z_-]*' LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    let fault: Option<i64> = connection.query_row(
        "SELECT 1 FROM bootstrap_arms b WHERE EXISTS (SELECT 1 FROM fault_cases f WHERE b.context_id=f.context_id OR b.context_nonce=f.context_nonce) LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    let active_collision: Option<i64> = connection.query_row(
        "SELECT 1 FROM bootstrap_arms b WHERE b.state IN (1, 2) AND (EXISTS (SELECT 1 FROM run_bootstraps r WHERE b.context_id=r.context_id OR b.context_nonce=r.context_nonce) OR EXISTS (SELECT 1 FROM replay_keys k WHERE (k.domain=1 AND k.replay_key=b.context_id) OR (k.domain=2 AND k.replay_key=b.context_nonce))) LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    let terminal_partial: Option<i64> = connection.query_row(
        "SELECT 1 FROM bootstrap_arms b WHERE b.state IN (3, 4) AND (EXISTS (SELECT 1 FROM run_bootstraps r WHERE b.context_id=r.context_id OR b.context_nonce=r.context_nonce) OR EXISTS (SELECT 1 FROM replay_keys k WHERE (k.domain=1 AND k.replay_key=b.context_id) OR (k.domain=2 AND k.replay_key=b.context_nonce))) AND NOT (EXISTS (SELECT 1 FROM run_bootstraps r WHERE b.context_id=r.context_id AND b.context_nonce=r.context_nonce AND b.source_revision=r.source_revision AND b.workflow_run_id=r.workflow_run_id AND b.namespace_sha256=r.namespace_sha256) AND EXISTS (SELECT 1 FROM replay_keys k WHERE k.domain=1 AND k.replay_key=b.context_id AND k.source_revision=b.source_revision AND k.workflow_run_id=b.workflow_run_id AND k.namespace_sha256=b.namespace_sha256) AND EXISTS (SELECT 1 FROM replay_keys k WHERE k.domain=2 AND k.replay_key=b.context_nonce AND k.source_revision=b.source_revision AND k.workflow_run_id=b.workflow_run_id AND k.namespace_sha256=b.namespace_sha256)) LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    let consumed_missing: Option<i64> = connection.query_row(
        "SELECT 1 FROM bootstrap_arms b WHERE b.state=4 AND NOT (EXISTS (SELECT 1 FROM run_bootstraps r WHERE b.context_id=r.context_id AND b.context_nonce=r.context_nonce AND b.source_revision=r.source_revision AND b.workflow_run_id=r.workflow_run_id AND b.namespace_sha256=r.namespace_sha256) AND EXISTS (SELECT 1 FROM replay_keys k WHERE k.domain=1 AND k.replay_key=b.context_id AND k.source_revision=b.source_revision AND k.workflow_run_id=b.workflow_run_id AND k.namespace_sha256=b.namespace_sha256) AND EXISTS (SELECT 1 FROM replay_keys k WHERE k.domain=2 AND k.replay_key=b.context_nonce AND k.source_revision=b.source_revision AND k.workflow_run_id=b.workflow_run_id AND k.namespace_sha256=b.namespace_sha256)) LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    Ok(invalid.is_none()
        && fault.is_none()
        && active_collision.is_none()
        && terminal_partial.is_none()
        && consumed_missing.is_none())
}
