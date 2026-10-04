use super::fixture::*;
mod cancellation_support;
mod provider;
mod recovery_cancel;
mod recovery_cancel_no_admission;
mod recovery_cancel_outbox_replay;
mod recovery_cancel_pre_effect;
mod recovery_cancel_race;
mod recovery_cancel_replay;
mod recovery_cancel_terminal;
mod rejection;
mod setup;
mod terminal_success;
mod unknown_failure;
use provider::FailureProvider;
use rejection::dispatch_rejected_generation;
use setup::PreparedFailureScenario;

use runne_application::ports::EventStore;
use runne_provider::ProviderTerminalDisposition;
use runne_provider::StreamCursor;
use runne_runtime::provider_execution::{ProviderEventJournalContext, RuntimeProviderExecution};
use runne_runtime::provider_redaction::{
    ProhibitedContentCredentialMatcher, ProviderEventRedactionBoundary,
};
use runne_store::schema::{
    ConnectionMode, read_authority_id, read_event_log_lineage_id,
    reopen_managed_connection_validated,
};

#[tokio::test(flavor = "current_thread")]
async fn restart_applies_only_exact_settled_remote_failure_and_releases_original_claim() {
    for disposition in [
        ProviderTerminalDisposition::RemoteFailed,
        ProviderTerminalDisposition::RemoteIncomplete,
    ] {
        run_failure_recovery_scenario(disposition).await;
    }
}

async fn run_failure_recovery_scenario(disposition: ProviderTerminalDisposition) {
    let PreparedFailureScenario {
        harness,
        service,
        taskrun_id,
        conversation_id,
        workspace_id,
        claim,
        begin_context,
        provider_claim,
        record,
        stream,
    } = setup::prepare_failure_scenario().await;
    let matcher = ProhibitedContentCredentialMatcher::new(service.prohibited_content.as_ref());
    let redaction = ProviderEventRedactionBoundary::new(
        service.tail_store.as_ref(),
        service.scanner_store.as_ref(),
        &matcher,
    );
    let runtime = RuntimeProviderExecution::new(
        service.keyring.as_ref(),
        service.runtime_store.as_ref(),
        service.profile.as_ref(),
        service.prohibited_content.as_ref(),
        &redaction,
    );
    runtime
        .preflight_existing_active_key(service.runtime_authority_id, service.database_generation)
        .unwrap();
    let context = ProviderEventJournalContext {
        attempt_id: provider_claim.attempt_id,
        fencing_token: provider_claim.fencing_token,
        call_digest_version: record.call_digest_version,
        profile_digest: record.profile_digest,
        runtime_generation: service.runtime_generation,
    };
    let scripted = FailureProvider { disposition };
    for sequence in 0..3 {
        runtime
            .next_and_commit(&scripted, &stream, StreamCursor::new(sequence), &context)
            .await
            .unwrap_or_else(|error| panic!("sequence {sequence}: {error:?}"));
    }
    runtime.finalize_terminal_output(&context).unwrap();
    assert_eq!(
        harness
            .store
            .provider_failure_recovery_candidates(None, 128)
            .unwrap()
            .candidates
            .len(),
        1
    );
    let conn = harness.writer_connection();
    let exact_settlement: Vec<u8> = conn
        .query_row(
            "SELECT settlement_digest FROM provider_dispatch_attempts WHERE attempt_id=?1",
            [provider_claim.attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_ne!(exact_settlement, vec![0; 32]);
    let authority = read_authority_id(&conn).unwrap().unwrap();
    let lineage = read_event_log_lineage_id(&conn).unwrap().unwrap();
    let valid_reopen = reopen_managed_connection_validated(
        std::path::Path::new(&harness.db_path),
        ConnectionMode::ValidatedReopen,
        |connection| {
            if read_authority_id(connection)? == Some(authority)
                && read_event_log_lineage_id(connection)? == Some(lineage)
            {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    )
    .unwrap();
    drop(valid_reopen);
    conn.execute(
        "UPDATE provider_dispatch_attempts SET settlement_digest=zeroblob(32) WHERE attempt_id=?1",
        [provider_claim.attempt_id.as_bytes()],
    )
    .unwrap();
    drop(service);
    let rejected_reopen = reopen_managed_connection_validated(
        std::path::Path::new(&harness.db_path),
        ConnectionMode::ValidatedReopen,
        |connection| {
            if read_authority_id(connection)? == Some(authority)
                && read_event_log_lineage_id(connection)? == Some(lineage)
            {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    );
    assert!(
        rejected_reopen.is_err(),
        "schema admission must reject the corrupt terminal settlement before recovery"
    );
    assert_eq!(
        harness
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        claim.new_version
    );
    assert_eq!(
        harness
            .store
            .load_text_generation_receipt_by_command(
                begin_context.command_id,
                &begin_context.idempotency_key
            )
            .unwrap()
            .phase,
        runne_application::ports::TextGenerationPhase::Started
    );
    assert_eq!(
        conn.query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "active"
    );
    conn.execute(
        "UPDATE provider_dispatch_attempts SET settlement_digest=?1 WHERE attempt_id=?2",
        rusqlite::params![exact_settlement, provider_claim.attempt_id.as_bytes()],
    )
    .unwrap();
    let valid_reopen = reopen_managed_connection_validated(
        std::path::Path::new(&harness.db_path),
        ConnectionMode::ValidatedReopen,
        |connection| {
            if read_authority_id(connection)? == Some(authority)
                && read_event_log_lineage_id(connection)? == Some(lineage)
            {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    )
    .unwrap();
    drop(valid_reopen);
    let restarted = harness
        .try_compose_openai_provider_at_generation(harness.generation())
        .await
        .unwrap();
    let receipt = harness
        .store
        .load_text_generation_receipt_by_command(
            begin_context.command_id,
            &begin_context.idempotency_key,
        )
        .unwrap();
    assert_eq!(
        receipt.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert_eq!(
        harness
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        claim.new_version + 1
    );
    assert_eq!(
        harness
            .query_connection()
            .query_row(
                "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "released"
    );
    assert_eq!(
        harness
            .query_connection()
            .query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    let rejected_run = dispatch_rejected_generation(
        &harness,
        &restarted,
        conversation_id,
        workspace_id,
        matches!(disposition, ProviderTerminalDisposition::RemoteIncomplete),
        false,
    )
    .await;
    drop(restarted);
    let again = harness
        .try_compose_openai_provider_at_generation(harness.generation())
        .await
        .unwrap();
    assert_eq!(
        harness
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        claim.new_version + 1
    );
    assert!(
        harness
            .store
            .provider_failure_recovery_candidates(None, 128)
            .unwrap()
            .candidates
            .is_empty()
    );
    let rejected_receipt = harness
        .store
        .load_text_generation_receipt_by_command(
            rejected_run.begin_context.command_id,
            &rejected_run.begin_context.idempotency_key,
        )
        .unwrap();
    assert_eq!(
        rejected_receipt.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert_eq!(
        harness
            .store
            .load_task_run(rejected_run.taskrun_id)
            .unwrap()
            .current_version,
        rejected_run.claim_version + 1
    );
    assert!(
        harness
            .store
            .provider_rejection_recovery_candidates(None, 128)
            .unwrap()
            .candidates
            .is_empty()
    );
    drop(again);
}
