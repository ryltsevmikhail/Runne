use runne_project_owner_authority::{
    AuthorityStateSnapshot, DurableAdmission, ExpectedReceiptV5Bindings,
    GitSubjectResolutionContext, PersistedAdmission, PrevalidatedRootSignedDestinationAllowlistV1,
    ResolvedGitSubject, VerifiedProductionSecurityReviewInstance,
    bind_prevalidated_destination_allowlist_v1, expected_receipt_v5_bindings,
    prevalidate_evidence_envelope_v2, prevalidate_promotion_authority_receipt_v5,
    prevalidate_promotion_bootstrap_v4, prevalidate_stage_envelope_v2, resolve_git_subject,
};

#[allow(dead_code)]
fn production_handles_compose_expected_receipt_bindings(
    review: &VerifiedProductionSecurityReviewInstance,
    subject: &ResolvedGitSubject,
    allowlist: &PrevalidatedRootSignedDestinationAllowlistV1,
) -> ExpectedReceiptV5Bindings {
    expected_receipt_v5_bindings(review, subject, allowlist)
}

#[allow(dead_code)]
fn production_subject_resolution(
    v4: &runne_project_owner_authority::PrevalidatedPromotionBootstrapV4,
    context: &dyn GitSubjectResolutionContext,
) -> Result<ResolvedGitSubject, runne_project_owner_authority::AuthorityError> {
    resolve_git_subject(v4, context)
}

#[allow(dead_code)]
struct PureChainInputs<'a> {
    trust3: &'a runne_project_owner_authority::VerifiedTrustConfigV3,
    v3: &'a runne_project_owner_authority::VerifiedDocumentReconciliation,
    v4_bytes: &'a [u8],
    v4_digest: [u8; 32],
    trust4: &'a runne_project_owner_authority::VerifiedTrustConfigV4,
    review: &'a VerifiedProductionSecurityReviewInstance,
    subject: &'a ResolvedGitSubject,
    allowlist: PrevalidatedRootSignedDestinationAllowlistV1,
    receipt_bytes: &'a [u8],
    receipt_digest: [u8; 32],
    stage_bytes: &'a [u8],
    stage_digest: [u8; 32],
    evidence_bytes: &'a [u8],
    evidence_digest: [u8; 32],
}

#[allow(dead_code)]
fn pure_chain_never_needs_an_admission_context(
    input: PureChainInputs<'_>,
) -> Result<(), runne_project_owner_authority::AuthorityError> {
    let v4 = prevalidate_promotion_bootstrap_v4(
        input.v4_bytes,
        input.v4_digest,
        input.trust3,
        input.v3,
    )?;
    let expected = expected_receipt_v5_bindings(input.review, input.subject, &input.allowlist);
    let v5 = prevalidate_promotion_authority_receipt_v5(
        input.receipt_bytes,
        input.receipt_digest,
        input.trust4,
        &v4,
        &expected,
    )?;
    let _stage = prevalidate_stage_envelope_v2(input.stage_bytes, input.stage_digest, &v5)?;
    let _evidence =
        prevalidate_evidence_envelope_v2(input.evidence_bytes, input.evidence_digest, &v5)?;
    let _allowlist = bind_prevalidated_destination_allowlist_v1(input.allowlist, &v5)?;
    Ok(())
}

#[allow(dead_code)]
fn exact_recovery_result(
    state: AuthorityStateSnapshot,
    persisted: PersistedAdmission,
) -> (AuthorityStateSnapshot, DurableAdmission) {
    (
        state.clone(),
        DurableAdmission::ExistingSame { persisted, state },
    )
}
