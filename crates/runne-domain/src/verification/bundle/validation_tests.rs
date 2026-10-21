use super::test_support::*;
use super::*;

// Catches a validator that rejects complete, internally matching self-reports.
#[test]
fn complete_metadata_is_support_not_authority() {
    let bundle = complete();
    let report = validate_structure(&bundle).unwrap();
    assert_eq!(
        report.historical_checks,
        vec![ScopedHistoricalCheck {
            slot: 1,
            reported_outcome: ReportedCheckOutcome::Passed,
            structural_support: StructuralSupport::Complete,
            missing: vec![],
        }]
    );
    assert_eq!(report.missing, vec![]);
}

// Catches individual optional omissions accidentally requiring another omission.
#[test]
fn each_optional_component_is_independently_incomplete() {
    for (field, missing) in [
        (0, MissingComponent::CheckBinding),
        (1, MissingComponent::Verifier),
        (2, MissingComponent::DeclaredAcceptance),
        (3, MissingComponent::ResultRef),
        (4, MissingComponent::EvidenceRefs),
    ] {
        let mut b = complete();
        match field {
            0 => b.checks[0].binding = None,
            1 => b.checks[0].verifier = None,
            2 => b.checks[0].declared_acceptance = None,
            3 => b.checks[0].result = None,
            _ => b.checks[0].evidence.clear(),
        }
        let r = validate_structure(&b).unwrap();
        assert_eq!(r.historical_checks[0].missing, vec![missing]);
        assert_eq!(
            r.historical_checks[0].structural_support,
            StructuralSupport::Incomplete
        );
    }
    let mut b = complete();
    b.plan_evaluation = None;
    let r = validate_structure(&b).unwrap();
    assert_eq!(r.missing, vec![MissingComponent::PlanEvaluationRef]);
    assert_eq!(
        r.historical_checks[0].structural_support,
        StructuralSupport::Complete
    );
    b.checked_snapshot
        .as_mut()
        .unwrap()
        .required_artifacts
        .clear();
    b.checks[0].binding = b.checked_snapshot.clone();
    assert_eq!(
        validate_structure(&b).unwrap().historical_checks[0].structural_support,
        StructuralSupport::Complete
    );
}

// Catches accepting inconsistent nested declarations as structural support.
#[test]
fn rejects_internal_snapshot_and_evaluation_mismatches() {
    for axis in 0..8 {
        let mut b = complete();
        let s = b.checks[0].binding.as_mut().unwrap();
        match axis {
            0 => s.taskrun_id = crate::id::TaskRunId::from_bytes(bytes(20)),
            1 => s.plan_id = crate::id::PlanId::from_bytes(bytes(20)),
            2 => s.task_revision += 1,
            3 => s.plan_revision += 1,
            4 => s.stream_head += 1,
            5 => s.source_snapshot_digest = crate::id::IntegrityDigest::from_bytes([20; 32]),
            6 => s.environment.revision += 1,
            _ => s.required_artifacts[0].artifact.result = result(20),
        }
        error(&b, BundleErrorCode::CheckBindingMismatch, 0);
    }
    let mut b = complete();
    b.taskrun_id = crate::id::TaskRunId::from_bytes(bytes(20));
    error(&b, BundleErrorCode::SnapshotTaskMismatch, 0);
    for axis in 0..4 {
        let mut b = complete();
        let p = b.plan_evaluation.as_mut().unwrap();
        match axis {
            0 => p.taskrun_id = crate::id::TaskRunId::from_bytes(bytes(20)),
            1 => p.plan_id = crate::id::PlanId::from_bytes(bytes(20)),
            2 => p.plan_revision += 1,
            _ => p.evaluated_stream_head += 1,
        }
        error(&b, BundleErrorCode::PlanEvaluationMismatch, 0);
    }
}

// Catches treating missing Passed metadata as complete or reviewer as a criterion.
#[test]
fn missing_components_are_exact_even_for_reported_passed() {
    let mut b = complete();
    b.checked_snapshot = None;
    b.plan_evaluation = None;
    b.checks[0].binding = None;
    b.checks[0].verifier = None;
    b.checks[0].declared_acceptance = None;
    b.checks[0].result = None;
    b.checks[0].evidence.clear();
    let r = validate_structure(&b).unwrap();
    assert_eq!(
        r.missing,
        vec![
            MissingComponent::CheckedSnapshot,
            MissingComponent::PlanEvaluationRef
        ]
    );
    assert_eq!(
        r.historical_checks[0].missing,
        vec![
            MissingComponent::CheckedSnapshot,
            MissingComponent::CheckBinding,
            MissingComponent::Verifier,
            MissingComponent::DeclaredAcceptance,
            MissingComponent::ResultRef,
            MissingComponent::EvidenceRefs
        ]
    );
    assert_eq!(
        r.historical_checks[0].structural_support,
        StructuralSupport::Incomplete
    );
    assert_eq!(
        r.historical_checks[0].reported_outcome,
        ReportedCheckOutcome::Passed
    );
}

// Catches cross-run/profile claims and noncanonical evidence ordering.
#[test]
fn evidence_scope_and_order_are_checked() {
    for axis in 0..3 {
        let mut b = complete();
        let mut e = b.checks[0].evidence[0].clone();
        e.evidence_ref_id = uid(21);
        match axis {
            0 => e.run_id = uid(22),
            1 => e.profile_id = uid(22),
            _ => {
                e.profile_digest =
                    crate::verification::digest::VerificationDigest::from_bytes([22; 32])
            }
        }
        b.checks[0].evidence.push(e);
        error(&b, BundleErrorCode::EvidenceScopeMismatch, 0);
    }
    for duplicate in [true, false] {
        let mut b = complete();
        let mut c = b.checks[0].clone();
        c.slot = if duplicate { 1 } else { 0 };
        b.checks.push(c);
        error(&b, BundleErrorCode::CheckOrder, 1);
        let mut b = complete();
        let mut a = b.checked_snapshot.as_ref().unwrap().required_artifacts[0].clone();
        a.slot = if duplicate { 1 } else { 0 };
        b.checked_snapshot
            .as_mut()
            .unwrap()
            .required_artifacts
            .push(a);
        error(&b, BundleErrorCode::ArtifactOrder, 1);
        let mut b = complete();
        let mut e = b.checks[0].evidence[0].clone();
        if !duplicate {
            e.evidence_ref_id = uid(1);
        }
        b.checks[0].evidence.push(e);
        error(&b, BundleErrorCode::EvidenceOrder, 1);
        let mut b = complete();
        b.tool_returns = vec![
            ReportedToolReturn {
                invocation_id: crate::id::InvocationId::from_bytes(bytes(2)),
                outcome: ToolReturnOutcome::Unknown,
            },
            ReportedToolReturn {
                invocation_id: crate::id::InvocationId::from_bytes(bytes(if duplicate {
                    2
                } else {
                    1
                })),
                outcome: ToolReturnOutcome::NotRun,
            },
        ];
        error(&b, BundleErrorCode::ToolOrder, 1);
        b.tool_returns.clear();
        b.effects = vec![
            ReportedEffect {
                effect_id: crate::id::EffectId::from_bytes(bytes(2)),
                outcome: ReportedEffectOutcome::Applied,
            },
            ReportedEffect {
                effect_id: crate::id::EffectId::from_bytes(bytes(if duplicate { 2 } else { 1 })),
                outcome: ReportedEffectOutcome::Uncertain,
            },
        ];
        error(&b, BundleErrorCode::EffectOrder, 1);
    }
}
