use runne_domain::{
    agent_loop::{StepOutcomeRecord, StepOutcomeType},
    id::{EffectId, IntegrityDigest, ResultId, StepId},
    reference::ResultRef,
};
use runne_store::store::taskrun_tool_invocation::ToolInvocationBindingV1;
use sha2::{Digest, Sha256};

/// Builds the one canonical deterministic outcome record for a verified D2 helper receipt.
pub(crate) fn expected_step_outcome(
    binding: &ToolInvocationBindingV1,
    content_digest: IntegrityDigest,
    receipt_digest: IntegrityDigest,
) -> Result<StepOutcomeRecord, ()> {
    let step_id = deterministic_id(
        &[
            b"RUNNE_D2_TOOL_STEP_V1\0".as_slice(),
            binding.semantic_digest.as_bytes(),
            content_digest.as_bytes(),
        ]
        .concat(),
    );
    let effect_id = deterministic_id(
        &[
            b"RUNNE_D2_TOOL_EFFECT_V1\0".as_slice(),
            binding.semantic_digest.as_bytes(),
        ]
        .concat(),
    );
    let result_id = deterministic_id(
        &[
            b"RUNNE_D2_TOOL_RESULT_V1\0".as_slice(),
            binding.semantic_digest.as_bytes(),
            content_digest.as_bytes(),
        ]
        .concat(),
    );
    let result_ref = ResultRef::new(
        ResultId::from_bytes(result_id),
        "application/vnd.runne.d2-tool-result.v1+json",
        content_digest,
    )
    .map_err(|_| ())?;
    Ok(StepOutcomeRecord {
        proposal_index: binding.key.proposal_index,
        step_id: StepId::from_bytes(step_id),
        outcome_type: StepOutcomeType::Succeeded,
        result_ref: Some(result_ref),
        effect_id: Some(EffectId::from_bytes(effect_id)),
        evidence_digests: vec![binding.semantic_digest, content_digest, receipt_digest],
    })
}

fn deterministic_id(bytes: &[u8]) -> [u8; 16] {
    let mut value: [u8; 16] = Sha256::digest(bytes)[..16]
        .try_into()
        .expect("digest prefix");
    value[6] = (value[6] & 0x0f) | 0x70;
    value[8] = (value[8] & 0x3f) | 0x80;
    value
}
