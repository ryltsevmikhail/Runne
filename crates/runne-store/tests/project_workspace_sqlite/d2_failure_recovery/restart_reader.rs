use super::*;
use runne_application::ports::ConversationTextRepository;

#[test]
fn early_cycle_restart_receipt_replays_across_two_reopens() {
    for proposing in [false, true] {
        let fixture = setup::prepare_before_cycle();
        let task_runs =
            super::super::taskrun_tool_invocation_positive::loop_task_runs_for_authority(
                &fixture.store,
                fixture.runtime_authority.clone(),
            );
        let cycle = task_runs
            .start_loop_cycle(
                &task_context(0xe3, "d2-restart-reader-cycle"),
                runne_application::commands::StartLoopCycleInput {
                    taskrun_id: fixture.taskrun_id,
                    expected_version: fixture.started.taskrun_version,
                },
            )
            .unwrap();
        let runne_application::commands::CommandOutcome::CycleStarted {
            cycle_id,
            mut new_version,
            ..
        } = cycle
        else {
            panic!("cycle start expected")
        };
        if proposing {
            let manifest = runne_domain::context::ContextManifestRef {
                manifest_id: runne_domain::id::ContextManifestId::from_bytes(
                    command(0xe4).into_bytes(),
                ),
                taskrun_id: fixture.taskrun_id,
                attempt_id: fixture.assignment.attempt_id,
                cycle_id,
                revision: 1,
                policy_revision: "d2-restart-context-v1".into(),
                integrity_digest: runne_domain::id::IntegrityDigest::from_bytes([0xe4; 32]),
            };
            let context = task_runs
                .commit_context(
                    &task_context(0xe5, "d2-restart-reader-context"),
                    runne_application::commands::CommitContextInput {
                        taskrun_id: fixture.taskrun_id,
                        expected_version: new_version,
                        cycle_id,
                        manifest_ref: manifest,
                    },
                )
                .unwrap();
            let runne_application::commands::CommandOutcome::ContextCommitted {
                new_version: committed_version,
                ..
            } = context
            else {
                panic!("context commit expected")
            };
            new_version = committed_version;
        }
        let recovery_epoch = register_recovery_epoch(&fixture);
        let terminal = finish_restart_at_head(
            &fixture,
            fixture.assignment.clone(),
            recovery_epoch,
            new_version,
        )
        .unwrap();
        assert_eq!(terminal.taskrun_version, new_version + 1);

        let fingerprint = CommandFingerprint::for_generate_conversation_text(
            &fixture.conversation_id,
            fixture.original.expected_version,
            &fixture.original.text,
        );
        let scope = IdempotencyScope {
            runtime_authority_id: fixture.runtime_authority.clone(),
            principal_id: fixture.generation_context.principal_id.clone(),
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation {
                conversation_id: fixture.conversation_id,
            },
        };
        for _ in 0..2 {
            let reopened = crate::validated_reopen::reopen_store(
                fixture.database.file.path(),
                fixture.identity,
                fixture.runtime_authority.clone(),
                guard(),
            )
            .unwrap();
            let lookup = reopened
                .lookup_text_generation_receipt(
                    fixture.generation_context.command_id,
                    &fixture.generation_context.idempotency_key,
                    &scope,
                    &fingerprint,
                )
                .unwrap();
            assert!(matches!(lookup,
                runne_application::ports::TextGenerationReceiptLookup::Duplicate { stored_result }
                    if stored_result == terminal));
            let duplicate = ConversationTextService::new(
                reopened.clone(),
                reopened.clone(),
                fixture.runtime_authority.clone(),
                guard(),
            )
            .finish_text(
                &fixture.generation_context,
                runne_application::commands::FinishConversationTextInput {
                    original: fixture.original.clone(),
                    started: fixture.started.clone(),
                    completion:
                        runne_application::commands::ConversationTextCompletion::D2ToolLoopRestart {
                            evidence: runne_application::ports::D2ToolLoopRestartEvidence {
                                assignment: fixture.assignment.clone(),
                                recovery_epoch,
                                expected_taskrun_head: new_version,
                            },
                        },
                },
            )
            .unwrap();
            assert_eq!(duplicate, terminal);
        }
    }
}
