use runne_provider_openai::canary::{
    AccountingDisposition, CANARY_DIGEST, CanaryAccounting, CanaryCandidate, CanaryIdentity,
    CanaryOverlay, CandidateDisposition, MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS, PROFILE_DIGEST,
    RESERVATION_MICRO_USD, TerminalUsage,
};
use sha2::{Digest, Sha256};

fn digest(domain: &str, components: &[&[u8]]) -> [u8; 32] {
    let mut preimage = Vec::new();
    for component in core::iter::once(domain.as_bytes()).chain(components.iter().copied()) {
        preimage.extend_from_slice(&(component.len() as u64).to_be_bytes());
        preimage.extend_from_slice(component);
    }
    Sha256::digest(preimage).into()
}

fn digest_bytes(value: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[7 + index * 2..9 + index * 2], 16).unwrap();
    }
    bytes
}
fn assert_profile_rejected(identity: CanaryIdentity) {
    assert!(matches!(
        CanaryCandidate::prepare(identity, CanaryOverlay::approved()),
        Err(CandidateDisposition::ProfileMismatch)
    ));
}

fn assert_overlay_rejected(overlay: CanaryOverlay) {
    assert!(matches!(
        CanaryCandidate::prepare(CanaryIdentity::canonical(), overlay),
        Err(CandidateDisposition::OverlayRejected)
    ));
}

#[test]
fn accepts_the_exact_compiled_candidate() {
    let candidate =
        CanaryCandidate::prepare(CanaryIdentity::canonical(), CanaryOverlay::approved())
            .expect("the compiled candidate must prepare");

    assert_eq!(candidate.profile_id(), "runne-openai-responses-text/1");
    assert_eq!(candidate.profile_revision(), 2);
    assert_eq!(candidate.candidate_digest(), CANARY_DIGEST);
    assert_eq!(candidate.provider(), "openai");
    assert_eq!(candidate.origin(), "https://api.openai.com");
    assert_eq!(candidate.method(), "POST");
    assert_eq!(candidate.path(), "/v1/responses");
    assert_eq!(candidate.request_model(), "gpt-5.5-2026-04-23");
    assert_eq!(candidate.model_id(), "gpt-5.5");
    assert_eq!(candidate.model_revision(), "2026-04-23");
    assert_eq!(candidate.service_tier(), "default");
    assert_eq!(
        candidate.pricing_revision(),
        "openai-gpt-5.5-standard-short-context-2026-07-31/1"
    );
    assert_eq!(candidate.disposition(), CandidateDisposition::NotActivated);
    assert_eq!(format!("{candidate:?}"), "CanaryCandidate");
}

#[test]
fn separates_profile_and_candidate_digests_with_closed_evidence() {
    let candidate =
        CanaryCandidate::prepare(CanaryIdentity::canonical(), CanaryOverlay::approved()).unwrap();
    let evidence = candidate.evidence();
    let profile = digest_bytes(PROFILE_DIGEST);
    let prompt = digest("runne.canary.prompt/1", &[b"Reply with exactly: OK"]);
    let result = digest("runne.canary.result/1", &[b"OK"]);
    let one = 1_u64.to_be_bytes();
    let zero = 0_u64.to_be_bytes();
    let sixteen = 16_u64.to_be_bytes();
    let request = digest(
        "runne.canary.request/1",
        &[
            &profile,
            b"POST",
            b"https://api.openai.com",
            b"/v1/responses",
            b"gpt-5.5-2026-04-23",
            b"default",
            &one,
            &[1],
            &prompt,
            &22_u64.to_be_bytes(),
            &[0],
            &[0],
            &[1],
            &[0],
            &[0],
            &[0],
            &zero,
            b"none",
            b"none",
            &sixteen,
            &[1],
            &[1],
        ],
    );
    let request_length = 384_u64.to_be_bytes();
    let candidate_digest = digest(
        "runne.canary.candidate/1",
        &[
            &profile,
            &request,
            &request_length,
            &prompt,
            &22_u64.to_be_bytes(),
            &result,
            &2_u64.to_be_bytes(),
        ],
    );

    assert_eq!(
        PROFILE_DIGEST,
        "sha256:9e04ed0d3cdeb99279433f01dfd44b2b67af80c076c5a63f45437f9880bae27e"
    );
    assert_eq!(
        CANARY_DIGEST,
        "sha256:cb8ae5e5132213fa4527a168c0c666346815bd211a71baafaaab47fc42889a7c"
    );
    assert_ne!(CANARY_DIGEST, PROFILE_DIGEST);
    assert_eq!(
        prompt,
        digest_bytes("sha256:1ff713bca9a5e1685124ed010e5d36ef30edb5d429d6a8145620df0b6ba9ad3d")
    );
    assert_eq!(
        result,
        digest_bytes("sha256:b7adb9b31484687cc9ea88e6a0f08c99e307b130e79677f6794d3f7ba575d1ad")
    );
    assert_eq!(
        request,
        digest_bytes("sha256:dd9e9bfbf7dd8415a25673df50640cc11fec21b8a3b441c75e6e8f0fe73e39c0")
    );
    assert_eq!(
        candidate_digest,
        digest_bytes("sha256:cb8ae5e5132213fa4527a168c0c666346815bd211a71baafaaab47fc42889a7c")
    );
    assert_eq!(candidate.candidate_digest(), CANARY_DIGEST);
    assert_eq!(evidence.candidate_digest(), &candidate_digest);
    assert_eq!(evidence.profile_digest(), &profile);
    assert_eq!(evidence.request_digest(), &request);
    assert_eq!(evidence.prompt_digest(), &prompt);
    assert_eq!(evidence.result_digest(), &result);
    assert_eq!(evidence.request_length(), 384);
    assert_eq!(evidence.prompt_length(), 22);
    assert_eq!(evidence.result_length(), 2);
    assert_eq!(format!("{evidence:?}"), "CanaryEvidence");
}

#[test]
fn accepts_the_profile_sidecar_but_rejects_candidate_digest_as_profile() {
    assert!(
        CanaryCandidate::prepare(
            CanaryIdentity::canonical().with_profile_digest(PROFILE_DIGEST),
            CanaryOverlay::approved(),
        )
        .is_ok()
    );
    assert_profile_rejected(CanaryIdentity::canonical().with_profile_digest(CANARY_DIGEST));
}

#[test]
fn rejects_each_changed_candidate_identity_field() {
    assert_profile_rejected(CanaryIdentity::canonical().with_profile_id("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_profile_revision(3));
    assert_profile_rejected(CanaryIdentity::canonical().with_profile_digest("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_provider("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_origin("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_method("GET"));
    assert_profile_rejected(CanaryIdentity::canonical().with_path("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_request_model("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_model_id("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_model_revision("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_service_tier("changed"));
    assert_profile_rejected(CanaryIdentity::canonical().with_pricing_revision("changed"));
}

#[test]
fn rejects_store_other_than_false() {
    assert_overlay_rejected(CanaryOverlay::approved().with_store(true));
}

#[test]
fn rejects_background_other_than_false() {
    assert_overlay_rejected(CanaryOverlay::approved().with_background(true));
}

#[test]
fn rejects_nonempty_tools() {
    assert_overlay_rejected(CanaryOverlay::approved().with_tools_empty(false));
}

#[test]
fn rejects_tool_choice_other_than_none() {
    assert_overlay_rejected(CanaryOverlay::approved().with_tool_choice_none(false));
}

#[test]
fn rejects_stream_other_than_true() {
    assert_overlay_rejected(CanaryOverlay::approved().with_stream(false));
}

#[test]
fn rejects_output_limit_other_than_sixteen() {
    assert_overlay_rejected(CanaryOverlay::approved().with_max_output_tokens(15));
    assert_overlay_rejected(CanaryOverlay::approved().with_max_output_tokens(17));
}

#[test]
fn accepts_only_one_exact_user_phrase() {
    let long_text = "x".repeat(65);
    let other_short_text = "x".repeat(64);

    assert!(
        CanaryCandidate::prepare(CanaryIdentity::canonical(), CanaryOverlay::approved()).is_ok()
    );
    assert_overlay_rejected(CanaryOverlay::empty());
    assert_overlay_rejected(CanaryOverlay::approved().with_second_user("Reply with exactly: OK"));
    assert_overlay_rejected(CanaryOverlay::assistant("Reply with exactly: OK"));
    assert_overlay_rejected(CanaryOverlay::user(&long_text));
    assert_overlay_rejected(CanaryOverlay::user(&other_short_text));
    assert_overlay_rejected(CanaryOverlay::user("No"));
}

#[test]
fn rejects_developer_entries_and_other_fixed_overlay_fields() {
    assert_overlay_rejected(CanaryOverlay::developer("Reply with exactly: OK"));
    assert_overlay_rejected(CanaryOverlay::approved().with_reasoning_none(false));
    assert_overlay_rejected(CanaryOverlay::approved().with_metadata(false));
    assert_overlay_rejected(CanaryOverlay::approved().with_previous_response(false));
    assert_overlay_rejected(CanaryOverlay::approved().with_retry(true));
    assert_overlay_rejected(CanaryOverlay::approved().with_redirect(true));
    assert_overlay_rejected(CanaryOverlay::approved().with_proxy(true));
}

#[test]
fn derives_the_fixed_budget_with_checked_tenths() {
    let accounting = CanaryAccounting::reconcile(
        TerminalUsage::new(MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS, 0),
        "openai-gpt-5.5-standard-short-context-2026-07-31/1",
    )
    .expect("fixed budget must reconcile");

    assert_eq!(RESERVATION_MICRO_USD, 1_760);
    assert_eq!(accounting.expected_cost_tenths(), 17_600);
    assert_eq!(accounting.expected_cost_micro_usd(), RESERVATION_MICRO_USD);
    assert_eq!(accounting.reserved_tenths(), 17_600);
    assert_eq!(accounting.remaining_tenths(), 0);
    assert_eq!(accounting.settlement_count(), 1);
    assert_eq!(accounting.disposition(), AccountingDisposition::Reconciled);
    assert_eq!(
        CanaryAccounting::checked_expected_cost_tenths(256, 16, 64),
        Ok(14_720)
    );
    let partial =
        CanaryAccounting::reconcile(TerminalUsage::new(1, 1, 0), accounting.pricing_revision())
            .unwrap();
    assert_eq!(partial.expected_cost_tenths(), 350);
    assert_eq!(partial.remaining_tenths(), 17_250);
}

#[test]
fn reports_checked_accounting_failures_without_values() {
    let uncached = u64::MAX / 50;
    let input = uncached + 1;

    assert_eq!(
        CanaryAccounting::checked_expected_cost_tenths(u64::MAX, 0, 0),
        Err(AccountingDisposition::Overflow)
    );
    assert_eq!(
        CanaryAccounting::checked_expected_cost_tenths(input, 1, 1),
        Err(AccountingDisposition::Overflow)
    );
    assert_eq!(
        CanaryAccounting::checked_remaining_tenths(0, 1),
        Err(AccountingDisposition::Underflow)
    );
    assert_eq!(
        CanaryAccounting::checked_expected_cost_tenths(0, 0, 1),
        Err(AccountingDisposition::CachedUnderflow)
    );
}

#[test]
fn rejects_usage_outside_the_hard_authorization_cap() {
    let pricing_revision = "openai-gpt-5.5-standard-short-context-2026-07-31/1";

    for usage in [
        TerminalUsage::new(257, 17, 0),
        TerminalUsage::new(401, 0, 0),
    ] {
        assert!(matches!(
            CanaryAccounting::reconcile(usage, pricing_revision),
            Err(AccountingDisposition::OverCap)
        ));
    }
}
