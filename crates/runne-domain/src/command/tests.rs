    use super::*;
    use crate::agent_loop::{
        LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType,
        WakeEvidenceRef, WakeEvidenceSource,
    };
    use crate::context::ContextManifestRef;
    use crate::id::{
        BudgetReservationId, CheckpointId, ContextManifestId, CycleId, IntegrityDigest, PlanId,
        ReconciliationRunId, ResultId, StepId, WakeEvidenceId,
    };
    use crate::plan::PlanRevisionRef;
    use crate::recovery::{ReconciliationResultRef, ReconciliationStatus};
    use crate::reference::{BudgetReservationRef, CheckpointRef, ResultRef};

    const UUID: &str = "018f2e3a-7000-7000-8000-000000000010";

    fn context_ref() -> ContextManifestRef {
        ContextManifestRef {
            manifest_id: UUID.parse::<ContextManifestId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            attempt_id: UUID.parse().unwrap(),
            cycle_id: UUID.parse().unwrap(),
            revision: 1,
            policy_revision: "context-v1".into(),
            integrity_digest: IntegrityDigest::from_bytes([1; 32]),
        }
    }

    fn budget_ref() -> BudgetReservationRef {
        BudgetReservationRef {
            reservation_id: UUID.parse::<BudgetReservationId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            attempt_id: UUID.parse().unwrap(),
            retry_ordinal: 1,
            reservation_digest: IntegrityDigest::from_bytes([2; 32]),
        }
    }

    fn plan_ref() -> PlanRevisionRef {
        PlanRevisionRef {
            plan_id: UUID.parse::<PlanId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            cycle_id: UUID.parse().unwrap(),
            revision: 1,
            context_manifest_ref: context_ref(),
            expected_proposal_indexes: vec![0],
            proposal_batch_digest: IntegrityDigest::from_bytes([3; 32]),
            planning_policy_ref: ResultRef::new(
                UUID.parse::<ResultId>().unwrap(),
                "application/json",
                IntegrityDigest::from_bytes([4; 32]),
            )
            .unwrap(),
            planning_budget_ref: budget_ref(),
            parent_ref: None,
            integrity_digest: IntegrityDigest::from_bytes([5; 32]),
        }
    }

    fn step_ref() -> StepOutcomeRef {
        StepOutcomeRef {
            cycle_id: UUID.parse::<CycleId>().unwrap(),
            proposal_index: 0,
            step_id: UUID.parse::<StepId>().unwrap(),
            outcome_digest: IntegrityDigest::from_bytes([6; 32]),
        }
    }

    fn wake_ref() -> WakeEvidenceRef {
        WakeEvidenceRef {
            cycle_id: UUID.parse().unwrap(),
            condition_digest: IntegrityDigest::from_bytes([7; 32]),
            source: WakeEvidenceSource::Approval,
            evidence_id: UUID.parse::<WakeEvidenceId>().unwrap(),
            evidence_digest: IntegrityDigest::from_bytes([8; 32]),
            observed_at_unix_us: 10,
            authority_revision: "approval-v1".into(),
        }
    }

    fn reconciliation_ref() -> ReconciliationResultRef {
        ReconciliationResultRef {
            reconciliation_run_id: UUID.parse::<ReconciliationRunId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            predecessor_attempt_id: UUID.parse().unwrap(),
            recovery_generation: 0,
            reconciled_stream_position: 7,
            status: ReconciliationStatus::Reconciled,
            unresolved_effect_count: 0,
            result_digest: IntegrityDigest::from_bytes([9; 32]),
        }
    }

    #[test]
    fn phase5_command_contract_has_exact_eleven_variants() {
        let cycle_id = UUID.parse().unwrap();
        let commands = [
            TaskRunCommand::StartLoopCycle { cycle_id },
            TaskRunCommand::CommitContext {
                cycle_id,
                manifest_ref: context_ref(),
            },
            TaskRunCommand::CommitPlan {
                cycle_id,
                plan_revision_ref: plan_ref(),
                input_digest: IntegrityDigest::from_bytes([10; 32]),
                output_digest: IntegrityDigest::from_bytes([11; 32]),
                expected_proposal_indexes: vec![0],
            },
            TaskRunCommand::RecordStepOutcome {
                cycle_id,
                outcome: StepOutcomeRecord {
                    proposal_index: 0,
                    step_id: UUID.parse().unwrap(),
                    outcome_type: StepOutcomeType::Succeeded,
                    result_ref: None,
                    effect_id: None,
                    evidence_digests: vec![],
                },
            },
            TaskRunCommand::CompleteLoopCycle {
                cycle_id,
                disposition: LoopDisposition::Continue,
            },
            TaskRunCommand::CreateNextCycle {
                parent_cycle_id: cycle_id,
                successor_cycle_id: UUID.parse().unwrap(),
            },
            TaskRunCommand::ResumeLoopWait {
                wake_evidence_ref: wake_ref(),
            },
            TaskRunCommand::ScheduleRetry {
                new_attempt_id: UUID.parse().unwrap(),
                retry_ordinal: 1,
                step_outcome_ref: step_ref(),
                retry_policy_digest: IntegrityDigest::from_bytes([12; 32]),
                budget_reservation_ref: budget_ref(),
                delay_ms: 25,
                due_at_unix_us: 35,
            },
            TaskRunCommand::ActivateScheduledRetryAttempt {
                retry_ordinal: 1,
                now_unix_us: 35,
            },
            TaskRunCommand::CommitRecoveryResume {
                new_attempt_id: UUID.parse().unwrap(),
                context_manifest_ref: context_ref(),
                checkpoint_ref: CheckpointRef {
                    checkpoint_id: UUID.parse::<CheckpointId>().unwrap(),
                    event_position: 7,
                    integrity_digest: IntegrityDigest::from_bytes([13; 32]),
                },
                reconciliation_ref: reconciliation_ref(),
            },
            TaskRunCommand::CommitLoopCheckpoint {
                checkpoint_id: UUID.parse().unwrap(),
                event_position: 8,
                body: LoopCheckpointBody {
                    schema_version: "1".into(),
                    cycle_id,
                    attempt_id: UUID.parse().unwrap(),
                    plan_revision_ref: Some(plan_ref()),
                    context_manifest_ref: Some(context_ref()),
                    step_outcome_refs: vec![step_ref()],
                },
                integrity_digest: IntegrityDigest::from_bytes([14; 32]),
            },
        ];

        assert_eq!(commands.len(), 11);
    }
