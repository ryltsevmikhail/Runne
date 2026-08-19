use runne_platform_ports::process::{
    ProcessLifecycleBindingV1, ProcessPlatformRequestV1, ProcessTerminalEvidenceV1,
};
use runne_security::process_contract::ValidatedProcessIntentV1;

use super::{
    ProcessClaimBindingV1, ProcessContractErrorV1, ProcessOutputBoundsV1, ProcessOutputCallerIdV1,
};

#[derive(Clone)]
pub(super) struct DispatchInputV1 {
    pub(super) digest: [u8; 32],
    pub(super) claim_binding: ProcessClaimBindingV1,
    pub(super) request: ProcessPlatformRequestV1,
    pub(super) binding: ProcessLifecycleBindingV1,
    pub(super) timeout_ticks: u64,
    pub(super) cancellation_permitted: bool,
    pub(super) output_bounds: ProcessOutputBoundsV1,
    pub(super) output_caller: ProcessOutputCallerIdV1,
}

impl DispatchInputV1 {
    /// CONTRACT_ONLY: runtime composition is intentionally deferred and this
    /// internal entry point has no public re-export.
    #[allow(dead_code)]
    pub(super) fn from_validated(
        intent: &ValidatedProcessIntentV1,
    ) -> Result<Self, ProcessContractErrorV1> {
        let binding = intent.lifecycle_binding();
        let digest = *intent.digest().as_bytes();
        let request = ProcessPlatformRequestV1::new(
            digest,
            intent.executable().clone(),
            intent.cwd().clone(),
        )
        .map_err(|_| ProcessContractErrorV1::PlatformRequestRejected)?;
        let output = intent.output_limits();
        let output_bounds = ProcessOutputBoundsV1::new(
            output.stdin(),
            output.stdout(),
            output.stderr(),
            output.combined(),
        )?;
        Ok(Self {
            digest,
            claim_binding: ProcessClaimBindingV1::from_lifecycle(&binding),
            request,
            binding,
            timeout_ticks: intent.timeout_ticks(),
            cancellation_permitted: intent.cancellation_permitted(),
            output_bounds,
            output_caller: ProcessOutputCallerIdV1::from_validated_label(
                *intent.output_caller_label().as_bytes(),
            )?,
        })
    }
}

pub(super) fn exact_terminal(
    evidence: &ProcessTerminalEvidenceV1,
    binding: &ProcessLifecycleBindingV1,
) -> bool {
    evidence.binding() == binding
}

pub(super) fn exact_verified_terminal(
    evidence: &ProcessTerminalEvidenceV1,
    binding: &ProcessLifecycleBindingV1,
) -> bool {
    exact_terminal(evidence, binding)
        && evidence.owner_verification()
            == runne_platform_ports::process::ProcessOwnerVerificationV1::Verified
        && evidence.tree_cleanup() == runne_platform_ports::process::ProcessTreeCleanupV1::Verified
}

pub(super) fn matches_claim(
    claim: &super::ProcessClaimInputV1,
    input: &DispatchInputV1,
    admission: &crate::EffectAdmission,
) -> bool {
    claim.key().permit_id() == admission.permit_id.as_str()
        && claim.binding() == &input.claim_binding
        && claim.intent_digest() == input.digest
        && input.claim_binding == ProcessClaimBindingV1::from_lifecycle(&input.binding)
}
