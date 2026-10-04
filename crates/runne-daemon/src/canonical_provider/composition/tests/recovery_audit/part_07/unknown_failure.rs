use super::*;
use provider::UnknownFailureProvider;
use runne_application::ports::ConversationRepository;

#[tokio::test(flavor = "current_thread")]
async fn unknown_usage_remote_failure_closes_from_authenticated_journal_and_holds_reserves() {
    for (disposition, cancel_before_recovery) in [
        (ProviderTerminalDisposition::RemoteFailed, false),
        (ProviderTerminalDisposition::RemoteIncomplete, false),
        (ProviderTerminalDisposition::RemoteFailed, true),
        (ProviderTerminalDisposition::RemoteIncomplete, true),
    ] {
        let scenario = setup::prepare_unknown_failure_scenario().await;
        if cancel_before_recovery {
            super::cancellation_support::request_public_cancellation(&scenario);
        }
        let PreparedFailureScenario {
            harness,
            service,
            taskrun_id,
            conversation_id,
            claim,
            provider_claim,
            record,
            stream,
            ..
        } = scenario;
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
            .preflight_existing_active_key(
                service.runtime_authority_id,
                service.database_generation,
            )
            .unwrap();
        let context = ProviderEventJournalContext {
            attempt_id: provider_claim.attempt_id,
            fencing_token: provider_claim.fencing_token,
            call_digest_version: record.call_digest_version,
            profile_digest: record.profile_digest,
            runtime_generation: service.runtime_generation,
        };
        for sequence in 0..3 {
            runtime
                .next_and_commit(
                    &UnknownFailureProvider { disposition },
                    &stream,
                    StreamCursor::new(sequence),
                    &context,
                )
                .await
                .unwrap();
        }
        runtime.finalize_terminal_output(&context).unwrap();
        let unknown = harness
            .store
            .provider_unknown_failure_recovery_candidates(None, 128)
            .unwrap();
        assert_eq!(unknown.candidates.len(), 1);
        assert_eq!(unknown.candidates[0].usage, None);
        assert_eq!(unknown.candidates[0].disposition, disposition);
        assert!(
            harness
                .store
                .provider_failure_recovery_candidates(None, 128)
                .unwrap()
                .candidates
                .is_empty()
        );

        let service_text = harness.text_service();
        let applied = if cancel_before_recovery {
            assert!(
                crate::canonical_provider::provider_failure_recovery::recover_exact_cancelled_taskrun(
                    &runtime,
                    &redaction,
                    &harness.store,
                    service_text.as_ref(),
                    taskrun_id,
                    claim.new_version + 1,
                )
                .unwrap()
            );
            1
        } else {
            crate::canonical_provider::provider_failure_recovery::recover_settled_failures(
                &runtime,
                &redaction,
                &harness.store,
                service_text.as_ref(),
            )
            .unwrap()
        };
        assert_eq!(applied, 1);
        let expected_state = if cancel_before_recovery {
            runne_domain::task_run::TaskRunState::Cancelled
        } else {
            runne_domain::task_run::TaskRunState::Failed
        };
        assert_eq!(
            runne_domain::task_run::TaskRun::replay(
                &harness.store.load_task_run(taskrun_id).unwrap().events
            )
            .unwrap()
            .state(),
            expected_state
        );
        let conversation = harness.store.load_conversation(conversation_id).unwrap();
        let expected_failure_reason = if cancel_before_recovery {
            runne_domain::conversation::GenerationFailureReason::Cancelled
        } else {
            runne_domain::conversation::GenerationFailureReason::ProviderExecutionFailed
        };
        assert!(conversation.events.iter().any(|event| matches!(
            event.payload(),
            runne_domain::conversation::ConversationEvent::GenerationFailed {
                reason,
                ..
            } if *reason == expected_failure_reason
        )));
        let connection = harness.writer_connection();
        let reserves = connection
            .prepare("SELECT state,settled_amount,released_at FROM provider_budget_reservations ORDER BY dimension")
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, Option<i64>>(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(reserves, vec![(1, None, None), (1, None, None)]);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM provider_accounting_settlements",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM provider_terminal_dispositions",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }
}
