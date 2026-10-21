use super::constraints::*;
use super::*;

/// Validate only bounded presence and internal consistency of self-reported metadata.
/// Does not authenticate identities, resolve refs, execute checks or confer authority.
pub fn validate_structure(b: &BundleMetadata) -> Result<StructuralReport, BundleError> {
    bounds(b)?;
    ensure(b.schema_version == 1, BundleErrorCode::UnsupportedSchema, 0)?;
    ensure(b.revision >= 1, BundleErrorCode::InvalidRevision, 0)?;
    identity(b.export_id.as_bytes(), 0)?;
    identity(b.taskrun_id.as_bytes(), 0)?;
    text(&b.producer_version, 0)?;
    if let Some(s) = &b.checked_snapshot {
        snapshot(s, 0)?;
        ensure(
            s.taskrun_id == b.taskrun_id,
            BundleErrorCode::SnapshotTaskMismatch,
            0,
        )?;
    }
    if let Some(p) = &b.plan_evaluation {
        identity(p.evaluation_id.as_bytes(), 0)?;
        identity(p.taskrun_id.as_bytes(), 0)?;
        identity(p.plan_id.as_bytes(), 0)?;
        if let Some(s) = &b.checked_snapshot {
            ensure(
                p.taskrun_id == s.taskrun_id
                    && p.plan_id == s.plan_id
                    && p.plan_revision == s.plan_revision
                    && p.evaluated_stream_head == s.stream_head,
                BundleErrorCode::PlanEvaluationMismatch,
                0,
            )?;
        }
    }
    order(b.checks.iter().map(|c| c.slot), BundleErrorCode::CheckOrder)?;
    order(
        b.tool_returns.iter().map(|t| t.invocation_id.as_bytes()),
        BundleErrorCode::ToolOrder,
    )?;
    order(
        b.effects.iter().map(|e| e.effect_id.as_bytes()),
        BundleErrorCode::EffectOrder,
    )?;
    for (i, t) in b.tool_returns.iter().enumerate() {
        identity(t.invocation_id.as_bytes(), i)?;
    }
    for (i, e) in b.effects.iter().enumerate() {
        identity(e.effect_id.as_bytes(), i)?;
    }
    // Validate all nested metadata before allocating the public report.
    for (i, c) in b.checks.iter().enumerate() {
        check(b, c, i)?;
    }
    let mut missing = vec![];
    if b.checked_snapshot.is_none() {
        missing.push(MissingComponent::CheckedSnapshot);
    }
    if b.plan_evaluation.is_none() {
        missing.push(MissingComponent::PlanEvaluationRef);
    }
    let historical_checks = b.checks.iter().map(|c| historical(b, c)).collect();
    Ok(StructuralReport {
        historical_checks,
        missing,
    })
}
fn check(b: &BundleMetadata, c: &ReportedCheck, i: usize) -> Result<(), BundleError> {
    if let Some(s) = &c.binding {
        snapshot(s, i)?;
        if let Some(checked) = &b.checked_snapshot {
            ensure(s == checked, BundleErrorCode::CheckBindingMismatch, i)?;
        }
    }
    if let Some(v) = &c.verifier {
        text(&v.id, i)?;
        text(&v.version, i)?;
    }
    if let Some(r) = &c.declared_acceptance {
        result(r, i)?;
    }
    if let Some(r) = &c.result {
        result(r, i)?;
    }
    order(
        c.evidence.iter().map(|e| e.evidence_ref_id.as_bytes()),
        BundleErrorCode::EvidenceOrder,
    )?;
    for e in &c.evidence {
        identity(e.evidence_ref_id.as_bytes(), i)?;
        identity(e.run_id.as_bytes(), i)?;
        identity(e.profile_id.as_bytes(), i)?;
        if let Some(first) = c.evidence.first() {
            ensure(
                e.run_id == first.run_id
                    && e.profile_id == first.profile_id
                    && e.profile_digest == first.profile_digest,
                BundleErrorCode::EvidenceScopeMismatch,
                i,
            )?;
        }
    }
    Ok(())
}
fn historical(b: &BundleMetadata, c: &ReportedCheck) -> ScopedHistoricalCheck {
    let mut missing = vec![];
    for (absent, component) in [
        (
            b.checked_snapshot.is_none(),
            MissingComponent::CheckedSnapshot,
        ),
        (c.binding.is_none(), MissingComponent::CheckBinding),
        (c.verifier.is_none(), MissingComponent::Verifier),
        (
            c.declared_acceptance.is_none(),
            MissingComponent::DeclaredAcceptance,
        ),
        (c.result.is_none(), MissingComponent::ResultRef),
        (c.evidence.is_empty(), MissingComponent::EvidenceRefs),
    ] {
        if absent {
            missing.push(component);
        }
    }
    ScopedHistoricalCheck {
        slot: c.slot,
        reported_outcome: c.outcome,
        structural_support: if missing.is_empty() {
            StructuralSupport::Complete
        } else {
            StructuralSupport::Incomplete
        },
        missing,
    }
}
