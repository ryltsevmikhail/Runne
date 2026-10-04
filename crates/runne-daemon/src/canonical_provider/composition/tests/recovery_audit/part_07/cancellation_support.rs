use super::super::fixture::Harness;
use super::setup::PreparedFailureScenario;
use runne_application::commands::CancelTaskRunInput;
use runne_application::ports::RuntimeAuthorityId;
use runne_application::service::TaskRunService;

pub(super) fn request_public_cancellation(scenario: &PreparedFailureScenario) {
    let service = TaskRunService::new(
        scenario.harness.store.clone(),
        scenario.harness.store.clone(),
        scenario.harness.store.clone(),
        RuntimeAuthorityId(hex::encode(scenario.service.runtime_authority_id)),
    );
    service
        .cancel_task_run(
            &super::super::super::command_context(
                "018f2e3a-7000-7000-8000-000000000102",
                "cancel-public",
            ),
            CancelTaskRunInput {
                taskrun_id: scenario.taskrun_id,
                expected_version: scenario.claim.new_version,
            },
        )
        .unwrap();
}

pub(super) fn pending_terminal_snapshot(harness: &Harness) -> PendingTerminal {
    let connection = harness.query_connection();
    pending_terminal_snapshot_on(&connection)
}

pub(super) fn pending_terminal_snapshot_on(connection: &rusqlite::Connection) -> PendingTerminal {
    connection
        .query_row(
            "SELECT state, receipt_digest, applied_at, settlement_digest, ciphertext
             FROM provider_terminal_outbox",
            [],
            |row| {
                Ok(PendingTerminal {
                    state: row.get(0)?,
                    receipt: row.get(1)?,
                    applied_at: row.get(2)?,
                    settlement: row.get(3)?,
                    ciphertext: row.get(4)?,
                })
            },
        )
        .unwrap()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PendingTerminal {
    pub(super) state: i64,
    pub(super) receipt: Option<Vec<u8>>,
    pub(super) applied_at: Option<i64>,
    pub(super) settlement: Vec<u8>,
    pub(super) ciphertext: Vec<u8>,
}
