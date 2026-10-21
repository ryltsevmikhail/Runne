use super::test_support::*;
use super::*;

// Catches treating caller-matching forged metadata as resolved authority/applicability.
#[test]
fn matching_self_reports_have_no_authority_or_applicability() {
    let b = complete();
    let p = project_declared_snapshot(&b, b.checked_snapshot.as_ref()).unwrap();
    assert_eq!(
        p.declared_snapshot_binding,
        DeclaredSnapshotBinding::MatchesDeclaredSnapshot
    );
    assert_eq!(p.authority_resolution, AuthorityResolution::NotPerformed);
    assert_eq!(
        p.current_applicability,
        CurrentApplicability::UnknownWithoutE2
    );
    assert_eq!(
        p.historical_checks[0].structural_support,
        StructuralSupport::Complete
    );
}

// Catches stale axes omitted, reordered, or used to rewrite historical outcomes.
#[test]
fn each_declared_axis_and_combined_changes_are_stale() {
    let b = complete();
    for (axis, want) in [
        (0, BindingAxis::TaskRevision),
        (1, BindingAxis::PlanRevision),
        (2, BindingAxis::StreamHead),
        (3, BindingAxis::SourceSnapshot),
        (4, BindingAxis::Environment),
        (5, BindingAxis::RequiredArtifacts),
    ] {
        let mut s = snapshot();
        change(&mut s, axis);
        let p = project_declared_snapshot(&b, Some(&s)).unwrap();
        assert_eq!(
            p.declared_snapshot_binding,
            DeclaredSnapshotBinding::StaleAgainstDeclaredSnapshot {
                changed: vec![want]
            }
        );
        assert_eq!(
            p.historical_checks[0].reported_outcome,
            ReportedCheckOutcome::Passed
        );
    }
    let mut s = snapshot();
    for i in 0..6 {
        change(&mut s, i);
    }
    assert_eq!(
        project_declared_snapshot(&b, Some(&s))
            .unwrap()
            .declared_snapshot_binding,
        DeclaredSnapshotBinding::StaleAgainstDeclaredSnapshot {
            changed: vec![
                BindingAxis::TaskRevision,
                BindingAxis::PlanRevision,
                BindingAxis::StreamHead,
                BindingAxis::SourceSnapshot,
                BindingAxis::Environment,
                BindingAxis::RequiredArtifacts
            ]
        }
    );
    for mutation in 0..6 {
        let mut s = snapshot();
        match mutation {
            0 => s.required_artifacts[0].artifact.result = result(30),
            1 => s.required_artifacts[0].artifact.revision += 1,
            2 => {
                s.required_artifacts[0].artifact.result = crate::reference::ResultRef::new(
                    *s.required_artifacts[0].artifact.result.result_id(),
                    "application/json",
                    crate::id::IntegrityDigest::from_bytes([30; 32]),
                )
                .unwrap()
            }
            3 => s.required_artifacts[0].slot = 2,
            4 => s.required_artifacts.clear(),
            _ => s.required_artifacts.push(ArtifactBinding {
                slot: 2,
                artifact: RevisionRef {
                    revision: 1,
                    result: result(30),
                },
            }),
        }
        assert_eq!(
            project_declared_snapshot(&b, Some(&s))
                .unwrap()
                .declared_snapshot_binding,
            DeclaredSnapshotBinding::StaleAgainstDeclaredSnapshot {
                changed: vec![BindingAxis::RequiredArtifacts]
            }
        );
    }
}
fn change(s: &mut DeclaredSnapshot, axis: u8) {
    match axis {
        0 => s.task_revision += 1,
        1 => s.plan_revision += 1,
        2 => s.stream_head += 1,
        3 => s.source_snapshot_digest = crate::id::IntegrityDigest::from_bytes([30; 32]),
        4 => s.environment.revision += 1,
        _ => s.required_artifacts[0].artifact.revision += 1,
    }
}

// Catches foreign-scope comparison mislabeled stale and malformed comparison ignored.
#[test]
fn comparison_is_validated_and_scope_checked_after_bundle_structure() {
    for axis in 0..2 {
        let b = complete();
        let mut s = snapshot();
        if axis == 0 {
            s.taskrun_id = crate::id::TaskRunId::from_bytes(bytes(30));
        } else {
            s.plan_id = crate::id::PlanId::from_bytes(bytes(30));
        }
        assert_eq!(
            project_declared_snapshot(&b, Some(&s)),
            Err(BundleError {
                code: BundleErrorCode::ComparisonScopeMismatch,
                ordinal: 0
            })
        );
    }
    let b = complete();
    let mut s = snapshot();
    s.plan_id = crate::id::PlanId::from_bytes([0; 16]);
    assert_eq!(
        project_declared_snapshot(&b, Some(&s)),
        Err(BundleError {
            code: BundleErrorCode::InvalidIdentity,
            ordinal: 0
        })
    );
    let mut bad = b.clone();
    bad.schema_version = 99;
    assert_eq!(
        project_declared_snapshot(&bad, Some(&s)),
        Err(BundleError {
            code: BundleErrorCode::UnsupportedSchema,
            ordinal: 0
        })
    );
    s.required_artifacts = vec![s.required_artifacts[0].clone(); 65];
    assert_eq!(
        project_declared_snapshot(&b, Some(&s)),
        Err(BundleError {
            code: BundleErrorCode::TooManyArtifacts,
            ordinal: 0
        })
    );
}

// Catches absent snapshots inferred as a match, or absent check binding inferred.
#[test]
fn absent_snapshots_are_unknown_with_exact_missing_codes() {
    let b = complete();
    assert_eq!(
        project_declared_snapshot(&b, None)
            .unwrap()
            .declared_snapshot_binding,
        DeclaredSnapshotBinding::Unknown {
            missing: vec![MissingComponent::ComparisonSnapshot]
        }
    );
    let mut b = b;
    b.checked_snapshot = None;
    assert_eq!(
        project_declared_snapshot(&b, Some(&snapshot()))
            .unwrap()
            .declared_snapshot_binding,
        DeclaredSnapshotBinding::Unknown {
            missing: vec![MissingComponent::CheckedSnapshot]
        }
    );
    assert_eq!(
        project_declared_snapshot(&b, None)
            .unwrap()
            .declared_snapshot_binding,
        DeclaredSnapshotBinding::Unknown {
            missing: vec![
                MissingComponent::CheckedSnapshot,
                MissingComponent::ComparisonSnapshot
            ]
        }
    );
    assert_eq!(
        validate_structure(&b).unwrap().historical_checks[0].missing,
        vec![MissingComponent::CheckedSnapshot]
    );
    let mut b = complete();
    b.checks[0].binding = None;
    assert_eq!(
        validate_structure(&b).unwrap().historical_checks[0].missing,
        vec![MissingComponent::CheckBinding]
    );
}

// Catches outcome uplift from evaluator, reviewer, override, provider, tools or effects.
#[test]
fn orthogonal_self_reports_never_uplift_and_input_is_unchanged() {
    use crate::verification::PlanEvaluationResult as P;
    for outcome in [
        ReportedCheckOutcome::Passed,
        ReportedCheckOutcome::Failed,
        ReportedCheckOutcome::Partial,
        ReportedCheckOutcome::Uncertain,
        ReportedCheckOutcome::Unsupported,
        ReportedCheckOutcome::NotRun,
    ] {
        for eval in [P::Passed, P::Failed, P::Blocked, P::RequiresReview] {
            let mut b = complete();
            b.checks[0].outcome = outcome;
            b.plan_evaluation.as_mut().unwrap().result = eval;
            b.effects.push(ReportedEffect {
                effect_id: crate::id::EffectId::from_bytes(bytes(31)),
                outcome: ReportedEffectOutcome::Uncertain,
            });
            let before = b.clone();
            for comparison in [Some(snapshot()), None] {
                let p = project_declared_snapshot(&b, comparison.as_ref()).unwrap();
                assert_eq!(p.historical_checks[0].reported_outcome, outcome);
                assert_eq!(p.authority_resolution, AuthorityResolution::NotPerformed);
                assert_eq!(
                    p,
                    project_declared_snapshot(&b, comparison.as_ref()).unwrap()
                );
            }
            assert_eq!(b, before);
        }
    }
    let mut b = complete();
    b.checks.clear();
    b.tool_returns.push(ReportedToolReturn {
        invocation_id: crate::id::InvocationId::from_bytes(bytes(30)),
        outcome: ToolReturnOutcome::Returned { exit_code: Some(0) },
    });
    assert!(
        project_declared_snapshot(&b, Some(&snapshot()))
            .unwrap()
            .historical_checks
            .is_empty()
    );
    assert_ne!(b.cost.model_compute, CostAmount::KnownUsdMicros(0));
}
