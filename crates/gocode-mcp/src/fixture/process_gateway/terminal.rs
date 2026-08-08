use gocode_tools::{
    ProcessHostOutcomeV1, ProcessOwnerVerificationV1, ProcessSettlementProofV1,
    ProcessTerminalResultV1, ProcessTreeCleanupV1, RawToolOutput, ToolCloseEvidence,
    ToolCloseRequest, ToolDispatchRequest, ToolExecutionHandle, ToolTerminalDisposition,
};

use super::super::runtime::process_ledger::{
    ProcessPhaseOutcome, ProcessReservationReceipt, ProcessUncertainReason,
};
use super::{McpProcessToolGateway, dispatch::settle_uncertain};

pub(super) fn settle_host_outcome(
    gateway: &McpProcessToolGateway,
    request: &ToolDispatchRequest,
    handle: ToolExecutionHandle,
    receipt: ProcessReservationReceipt,
) -> ProcessPhaseOutcome {
    let outcome = gateway
        .outcomes
        .lock()
        .ok()
        .and_then(|mut outcomes| outcomes.remove(&handle.execution_id));
    match outcome {
        Some(ProcessHostOutcomeV1::Terminal(result)) => {
            let evidence = close_evidence(&result);
            let Some(evidence) = evidence else {
                return settle_uncertain(gateway, receipt, ProcessUncertainReason::Lifecycle);
            };
            match gateway.gateway.close(ToolCloseRequest {
                invocation_id: request.invocation_id.clone(),
                request_digest: request.request_digest,
                handle,
                evidence,
                output: RawToolOutput::default(),
            }) {
                Ok(ToolTerminalDisposition::Completed(_)) => complete(gateway, request, receipt),
                Ok(ToolTerminalDisposition::Uncertain) | Err(_) => {
                    settle_uncertain(gateway, receipt, ProcessUncertainReason::Cleanup)
                }
            }
        }
        Some(ProcessHostOutcomeV1::State(_)) => {
            settle_uncertain(gateway, receipt, ProcessUncertainReason::State)
        }
        Some(ProcessHostOutcomeV1::Denied) => {
            settle_uncertain(gateway, receipt, ProcessUncertainReason::Denied)
        }
        None => settle_uncertain(gateway, receipt, ProcessUncertainReason::Host),
    }
}

fn complete(
    gateway: &McpProcessToolGateway,
    request: &ToolDispatchRequest,
    receipt: ProcessReservationReceipt,
) -> ProcessPhaseOutcome {
    let pending = gateway
        .pending
        .lock()
        .ok()
        .and_then(|mut pending| pending.remove(&request.invocation_id));
    let Some(pending) = pending else {
        return gateway
            .ledger
            .settle_uncertain(receipt, ProcessUncertainReason::Pending);
    };
    gateway.ledger.settle_completed(receipt, pending)
}

#[derive(Clone, Copy)]
struct TerminalCloseInput {
    completed: bool,
    owner: ProcessOwnerVerificationV1,
    cleanup: ProcessTreeCleanupV1,
}

impl From<&ProcessTerminalResultV1> for TerminalCloseInput {
    fn from(result: &ProcessTerminalResultV1) -> Self {
        Self {
            completed: matches!(
                result.settlement().proof(),
                ProcessSettlementProofV1::Completed(_)
            ),
            owner: result.settlement().owner_verification(),
            cleanup: result.settlement().tree_cleanup(),
        }
    }
}

fn close_evidence(result: &ProcessTerminalResultV1) -> Option<ToolCloseEvidence> {
    classify_close(TerminalCloseInput::from(result))
}

fn classify_close(input: TerminalCloseInput) -> Option<ToolCloseEvidence> {
    (input.completed
        && input.owner == ProcessOwnerVerificationV1::Verified
        && input.cleanup == ProcessTreeCleanupV1::Verified)
        .then_some(ToolCloseEvidence {
            process_terminal: true,
            containment_released: true,
            cleanup_closed: true,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_classifier_requires_completed_verified_owner_and_cleanup() {
        for completed in [true, false] {
            for owner in [
                ProcessOwnerVerificationV1::Verified,
                ProcessOwnerVerificationV1::Mismatch,
                ProcessOwnerVerificationV1::Unavailable,
                ProcessOwnerVerificationV1::NotApplicable,
            ] {
                for cleanup in [
                    ProcessTreeCleanupV1::Verified,
                    ProcessTreeCleanupV1::Unverified,
                    ProcessTreeCleanupV1::Unavailable,
                    ProcessTreeCleanupV1::NotApplicable,
                ] {
                    let evidence = classify_close(TerminalCloseInput {
                        completed,
                        owner,
                        cleanup,
                    });
                    assert_eq!(
                        evidence.is_some(),
                        completed
                            && owner == ProcessOwnerVerificationV1::Verified
                            && cleanup == ProcessTreeCleanupV1::Verified,
                        "completed={completed:?}, owner={owner:?}, cleanup={cleanup:?}"
                    );
                }
            }
        }
    }
}
