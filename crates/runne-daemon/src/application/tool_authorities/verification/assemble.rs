use super::*;
#[allow(clippy::too_many_arguments)]
pub(super) fn assemble(
    taskrun_id: runne_domain::id::TaskRunId,
    plan: &runne_domain::plan::PlanRevisionRef,
    stream_head: u64,
    requested: Option<&PlanEvaluationRef>,
    evidence: Vec<u8>,
    evaluated_at_unix_us: i64,
    coding: bool,
) -> Result<PlanEvaluation, VerificationQueryError> {
    let gate_definitions_digest = hash(if coding {
        b"RUNNE_CODING_TOOL_GATES_V1\0"
    } else {
        b"D2_SAFE_TOOL_GATES_V1\0workspace-read+create-new"
    });
    let evidence_set_digest = hash(&evidence);
    let mut evaluation_input = Vec::new();
    evaluation_input.extend_from_slice(taskrun_id.as_bytes());
    evaluation_input.extend_from_slice(plan.plan_id.as_bytes());
    evaluation_input.extend_from_slice(&plan.revision.to_be_bytes());
    evaluation_input.extend_from_slice(&stream_head.to_be_bytes());
    evaluation_input.extend_from_slice(gate_definitions_digest.as_bytes());
    evaluation_input.extend_from_slice(evidence_set_digest.as_bytes());
    let evaluation_digest = hash(&evaluation_input);
    let expected = PlanEvaluationRef {
        evaluation_id: deterministic_evaluation_id(evaluated_at_unix_us, evaluation_digest),
        taskrun_id,
        plan_id: plan.plan_id,
        plan_revision: plan.revision,
        evaluated_stream_head: stream_head,
        result: PlanEvaluationResult::Passed,
        gate_definitions_digest,
        evidence_set_digest,
        evaluation_digest,
    };
    if requested.is_some_and(|requested| requested != &expected) {
        return Err(VerificationQueryError::DigestMismatch);
    }
    let gate_evaluation_refs = if coding {
        vec!["coding-tool-receipts"]
    } else {
        vec!["workspace-read", "workspace-create-new"]
    }
    .into_iter()
    .map(|gate_id| GateEvaluationRef {
        gate_id: gate_id.into(),
        evidence_digest: evidence_set_digest,
        result_digest: evaluation_digest,
    })
    .collect();
    Ok(PlanEvaluation {
        reference: expected,
        gate_evaluation_refs,
        evaluated_at_unix_us,
        superseded_by: None,
    })
}

pub(super) fn latest_targets(
    records: &[&runne_store::store::taskrun_tool_invocation::ToolInvocationStoredRecord],
) -> (std::collections::BTreeMap<String, u32>, Option<u32>) {
    let latest = records
        .iter()
        .map(|r| (r.binding.target_name.clone(), r.binding.key.proposal_index))
        .collect();
    let command = records
        .iter()
        .filter(|r| r.binding.tool_name == "workspace.command.run")
        .map(|r| r.binding.key.proposal_index)
        .max();
    (latest, command)
}
