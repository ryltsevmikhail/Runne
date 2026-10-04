use super::*;

async fn read_effects(
    usage: Option<runne_provider::ProviderUsage>,
    tail: u8,
    request_cancellation: bool,
    requested_input_tokens: u64,
) {
    let mut fixture =
        super::super::super::fixture::running_without_provider_admission("source1-effects", tail);
    super::stream::dispatch(&mut fixture, requested_input_tokens);
    let durable_input = fixture
        .database
        .connection()
        .query_row(
            "SELECT requested_input_tokens FROM provider_execution_admissions WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(
        durable_input,
        i64::try_from(requested_input_tokens).unwrap()
    );
    let keyring = std::sync::Arc::new(super::super::super::effect::Keyring);
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &UnusedPricing,
        &AllowContent,
        &Redaction,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let context = stream_context(&fixture);
    let provider = Events(terminal_events(usage));
    for sequence in 0..4 {
        runtime
            .next_and_commit(
                &provider,
                &ProviderStreamId::from_bytes(*context.attempt_id.as_bytes()),
                StreamCursor::new(sequence),
                &context,
            )
            .await
            .unwrap();
    }
    assert_eq!(
        runtime.finalize_terminal_output(&context),
        Ok(runne_application::provider::ProviderTerminalCommitOutcome::Committed)
    );
    let token_reservation = fixture
        .database
        .connection()
        .query_row(
            "SELECT r.amount,r.state,r.settled_amount
             FROM provider_budget_reservations r
             JOIN provider_execution_admissions a USING(provider_idempotency_key)
             WHERE a.taskrun_id=?1 AND r.dimension=1",
            [fixture.taskrun_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .unwrap();
    assert!(token_reservation.0 > 0);
    assert_eq!(token_reservation.1, 1);
    assert_eq!(token_reservation.2, None);
    if request_cancellation {
        runne_application::service::TaskRunService::new(
            fixture.database.store.clone(),
            fixture.database.store.clone(),
            fixture.database.store.clone(),
            super::super::runtime_authority(),
        )
        .cancel_task_run(
            &super::super::context(tail + 3, "source1-effects-cancel"),
            runne_application::commands::CancelTaskRunInput {
                taskrun_id: fixture.taskrun_id,
                expected_version: fixture.version,
            },
        )
        .unwrap();
    }

    let authenticator = RuntimeProviderRemoteIdentityCommitter::new(
        std::sync::Arc::clone(&keyring),
        std::sync::Arc::clone(&fixture.execution),
    );
    let snapshot = fixture
        .database
        .store
        .load_task_run_effects_with_fact_authenticators(
            fixture.taskrun_id,
            None,
            Some(&authenticator),
            Some(&super::super::Resolver),
        )
        .unwrap();
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Unknown
    );
    assert_eq!(snapshot.effects.remote.usage_known, Some(usage.is_some()));
    assert_eq!(
        snapshot.effects.remote.publication,
        runne_api::RemotePublicationV1::Withheld
    );
    assert_eq!(
        snapshot.effects.remote.cancellation,
        if request_cancellation {
            runne_api::RemoteCancellationV1::Unconfirmed
        } else {
            runne_api::RemoteCancellationV1::NotRequested
        }
    );
    assert!(snapshot.source1.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_effects_read_authenticates_source1_completion_without_usage_or_remote_id() {
    read_effects(None, 0x61, false, 512).await;
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_effects_keep_actual_usage_known_when_pricing_is_unavailable() {
    read_effects(
        Some(runne_provider::ProviderUsage::new(3, 4, 1, 2).unwrap()),
        0x62,
        false,
        512,
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_effects_keep_completed_fact_when_taskrun_cancellation_is_pending() {
    read_effects(None, 0x63, true, 512).await;
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_effects_accept_lawful_zero_input_reservation_with_missing_usage() {
    read_effects(None, 0x64, false, 0).await;
}
