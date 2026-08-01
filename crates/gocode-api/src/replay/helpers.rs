fn bounded_failure_reason(reason: &str) -> Result<String, CanonicalReplayPayloadError> {
    if reason.is_empty() || reason.len() > MAX_CANONICAL_REPLAY_FAILURE_REASON_BYTES {
        return Err(CanonicalReplayPayloadError::InvalidFailureReason);
    }
    Ok(reason.to_owned())
}

const fn generation_failure_reason(reason: GenerationFailureReason) -> &'static str {
    match reason {
        GenerationFailureReason::ProviderOutputRejected => "provider_output_rejected",
    }
}

const fn step_outcome_type(outcome: StepOutcomeType) -> &'static str {
    match outcome {
        StepOutcomeType::Succeeded => "succeeded",
        StepOutcomeType::FailedBeforeCommit => "failed_before_commit",
        StepOutcomeType::FailedAfterCommit => "failed_after_commit",
        StepOutcomeType::Uncertain => "uncertain",
        StepOutcomeType::Cancelled => "cancelled",
    }
}

const fn loop_disposition(disposition: &LoopDisposition) -> &'static str {
    match disposition {
        LoopDisposition::Continue => "continue",
        LoopDisposition::Wait { .. } => "wait",
        LoopDisposition::Complete { .. } => "complete",
        LoopDisposition::Fail { .. } => "fail",
    }
}

const fn wake_evidence_source(source: WakeEvidenceSource) -> &'static str {
    match source {
        WakeEvidenceSource::ExternalInput => "external_input",
        WakeEvidenceSource::Approval => "approval",
        WakeEvidenceSource::ChildTaskRun => "child_task_run",
        WakeEvidenceSource::Timer => "timer",
        WakeEvidenceSource::Reconciliation => "reconciliation",
    }
}
