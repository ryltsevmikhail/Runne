use super::test_support::*;
use super::*;

// Catches missing list bounds and ensures bounds win before malformed nested IDs.
#[test]
fn collection_boundaries_and_preflight_precedence() {
    for (kind, n, code) in [
        (0, 32, BundleErrorCode::TooManyChecks),
        (1, 64, BundleErrorCode::TooManyArtifacts),
        (2, 16, BundleErrorCode::TooManyEvidenceRefs),
        (3, 64, BundleErrorCode::TooManyToolReturns),
        (4, 64, BundleErrorCode::TooManyEffects),
    ] {
        let mut b = complete();
        match kind {
            0 => {
                b.checks = (0..n)
                    .map(|i| {
                        let mut c = b.checks[0].clone();
                        c.slot = i as u16;
                        c
                    })
                    .collect()
            }
            1 => {
                let a = b.checked_snapshot.as_ref().unwrap().required_artifacts[0].clone();
                b.checked_snapshot.as_mut().unwrap().required_artifacts = (0..n)
                    .map(|i| {
                        let mut a = a.clone();
                        a.slot = i as u16;
                        a
                    })
                    .collect();
                b.checks[0].binding = b.checked_snapshot.clone();
            }
            2 => {
                b.checks[0].evidence = (0..n)
                    .map(|i| {
                        let mut e = b.checks[0].evidence[0].clone();
                        e.evidence_ref_id = uid(i as u8);
                        e
                    })
                    .collect()
            }
            3 => {
                b.tool_returns = (0..n)
                    .map(|i| ReportedToolReturn {
                        invocation_id: crate::id::InvocationId::from_bytes(bytes(i as u8)),
                        outcome: ToolReturnOutcome::Unknown,
                    })
                    .collect()
            }
            _ => {
                b.effects = (0..n)
                    .map(|i| ReportedEffect {
                        effect_id: crate::id::EffectId::from_bytes(bytes(i as u8)),
                        outcome: ReportedEffectOutcome::Unknown,
                    })
                    .collect()
            }
        }
        assert!(validate_structure(&b).is_ok(), "kind {kind}");
        match kind {
            0 => b.checks.push(b.checks[0].clone()),
            1 => {
                let s = b.checked_snapshot.as_mut().unwrap();
                s.required_artifacts.push(s.required_artifacts[0].clone());
            }
            2 => {
                let e = b.checks[0].evidence[0].clone();
                b.checks[0].evidence.push(e);
            }
            3 => b.tool_returns.push(b.tool_returns[0].clone()),
            _ => b.effects.push(b.effects[0].clone()),
        }
        b.taskrun_id = crate::id::TaskRunId::from_bytes([0; 16]);
        error(&b, code, 0);
    }
}

// Catches schema/revision/string/UUID validation bypasses via typed constructors.
#[test]
fn scalar_boundaries_and_unchecked_ids() {
    let mut b = complete();
    b.schema_version = 2;
    error(&b, BundleErrorCode::UnsupportedSchema, 0);
    let mut b = complete();
    b.revision = 0;
    error(&b, BundleErrorCode::InvalidRevision, 0);
    for field in 0..3 {
        for s in ["x".repeat(64), "é".repeat(32)] {
            let mut b = complete();
            set_string(&mut b, field, s);
            assert!(validate_structure(&b).is_ok());
        }
        for s in [
            String::new(),
            "x".repeat(65),
            "é".repeat(33),
            "a\nb".into(),
            "a\u{0085}b".into(),
        ] {
            let mut b = complete();
            set_string(&mut b, field, s);
            error(&b, BundleErrorCode::InvalidString, 0);
        }
    }
    for field in 0..14 {
        let mut b = complete();
        match field {
            0 => b.export_id = uuid::Uuid::nil(),
            1 => b.taskrun_id = crate::id::TaskRunId::from_bytes([0; 16]),
            2 => {
                b.checked_snapshot.as_mut().unwrap().taskrun_id =
                    crate::id::TaskRunId::from_bytes([0; 16])
            }
            3 => {
                b.checked_snapshot.as_mut().unwrap().plan_id =
                    crate::id::PlanId::from_bytes([0; 16])
            }
            4 => b.checked_snapshot.as_mut().unwrap().environment.result = bad_result(),
            5 => {
                b.checked_snapshot.as_mut().unwrap().required_artifacts[0]
                    .artifact
                    .result = bad_result()
            }
            6 => b.checks[0].declared_acceptance = Some(bad_result()),
            7 => b.checks[0].result = Some(bad_result()),
            8 => b.checks[0].evidence[0].evidence_ref_id = uuid::Uuid::nil(),
            9 => b.checks[0].evidence[0].run_id = uuid::Uuid::nil(),
            10 => b.checks[0].evidence[0].profile_id = uuid::Uuid::nil(),
            11 => {
                b.plan_evaluation.as_mut().unwrap().evaluation_id =
                    crate::id::PlanEvaluationId::from_bytes([0; 16])
            }
            12 => b.tool_returns.push(ReportedToolReturn {
                invocation_id: crate::id::InvocationId::from_bytes([0; 16]),
                outcome: ToolReturnOutcome::Unknown,
            }),
            _ => b.effects.push(ReportedEffect {
                effect_id: crate::id::EffectId::from_bytes([0; 16]),
                outcome: ReportedEffectOutcome::Unknown,
            }),
        }
        error(&b, BundleErrorCode::InvalidIdentity, 0);
    }
}
fn set_string(b: &mut BundleMetadata, field: u8, s: String) {
    match field {
        0 => b.producer_version = s,
        1 => b.checks[0].verifier.as_mut().unwrap().id = s,
        _ => b.checks[0].verifier.as_mut().unwrap().version = s,
    }
}
fn bad_result() -> crate::reference::ResultRef {
    crate::reference::ResultRef::new(
        crate::id::ResultId::from_bytes([0; 16]),
        "text/plain",
        crate::id::IntegrityDigest::from_bytes([0; 32]),
    )
    .unwrap()
}
