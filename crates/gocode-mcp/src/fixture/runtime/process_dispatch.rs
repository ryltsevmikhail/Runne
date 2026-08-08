use std::sync::{Arc, Mutex};

use super::process_ledger::{
    ProcessPhaseOutcome, ProcessPreEffectFailure, ProcessRefundReason, ProcessReserveOutcome,
    ProcessUncertainReason, refund_process, reserve_process,
};
use super::{
    FixtureApproval, FixtureApprovalPolicy, FixtureCallCapability, FixtureCallResult,
    FixtureMcpFailure, FixtureMcpRuntime, FixtureState,
};
use crate::fixture::process_gateway::{McpProcessGatewayError, McpProcessToolGateway};

pub(super) fn dispatch(
    runtime: &FixtureMcpRuntime,
    capability: &mut FixtureCallCapability,
    approval: Option<&FixtureApproval>,
) -> Result<FixtureCallResult, FixtureMcpFailure> {
    validate_l1(runtime, capability, approval)?;
    let state = Arc::clone(&runtime.state);
    let key = capability
        .process_key()
        .cloned()
        .ok_or(FixtureMcpFailure::CapabilityConsumed)?;
    let gateway = runtime
        .process_gateway
        .as_ref()
        .ok_or(FixtureMcpFailure::ProcessSandboxUnavailable)?;
    let payload = capability
        .process_payload
        .as_ref()
        .ok_or(FixtureMcpFailure::CapabilityConsumed)?;
    let verified = match McpProcessToolGateway::verify_c2b(payload) {
        Ok(verified) => verified,
        Err(error) => return Err(map_gateway_error(error)),
    };
    let claimed = match gateway.claim_verified(verified) {
        Ok(claimed) => claimed,
        Err(error) => return Err(map_gateway_error(error)),
    };
    revalidate_active(&state, capability)?;
    match reserve_process(&state, key)? {
        ProcessReserveOutcome::Owner(receipt) => {
            let payload = capability
                .take_process_payload()
                .ok_or(FixtureMcpFailure::CapabilityConsumed)?;
            map_phase_outcome(
                &state,
                capability,
                gateway.dispatch_claimed(claimed, receipt, payload),
            )
        }
        ProcessReserveOutcome::BusyReserved => Err(FixtureMcpFailure::ProcessReservationBusy),
        ProcessReserveOutcome::InvocationConflict => Err(FixtureMcpFailure::InvocationConflict),
        ProcessReserveOutcome::TerminalReplay(result) => match result {
            FixtureCallResult::Completed => Ok(FixtureCallResult::Completed),
            FixtureCallResult::Uncertain => Err(FixtureMcpFailure::DispatchUncertain),
            FixtureCallResult::Cancelled | FixtureCallResult::Disconnected => {
                Err(FixtureMcpFailure::InvalidStateTransition)
            }
        },
    }
}

fn validate_l1(
    runtime: &FixtureMcpRuntime,
    capability: &FixtureCallCapability,
    approval: Option<&FixtureApproval>,
) -> Result<(), FixtureMcpFailure> {
    if runtime
        .state
        .lock()
        .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?
        .tick
        > capability.expires_at
    {
        return Err(FixtureMcpFailure::CapabilityExpired);
    }
    let tool = runtime
        .tools
        .iter()
        .find(|tool| tool.name() == capability.tool_name)
        .ok_or(FixtureMcpFailure::ToolNotAllowed)?;
    if !runtime.allowlist.contains(tool.name()) {
        return Err(FixtureMcpFailure::ToolNotAllowed);
    }
    if tool.execution_class() != capability.execution_class() {
        return Err(FixtureMcpFailure::ExecutionClassMismatch);
    }
    match runtime.policy {
        FixtureApprovalPolicy::AlwaysDeny => Err(FixtureMcpFailure::ApprovalRequired),
        FixtureApprovalPolicy::ExplicitPerCall | FixtureApprovalPolicy::PreApprovedExactIntent
            if approval != Some(&FixtureApproval(capability.approval_digest)) =>
        {
            Err(FixtureMcpFailure::ApprovalMismatch)
        }
        _ => Ok(()),
    }
}

fn revalidate_active(
    state: &Arc<Mutex<FixtureState>>,
    capability: &FixtureCallCapability,
) -> Result<(), FixtureMcpFailure> {
    let state = state
        .lock()
        .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
    let active = state
        .active
        .as_ref()
        .ok_or(FixtureMcpFailure::InvalidStateTransition)?;
    if active.connection_id.as_str() != capability.connection_id {
        return Err(FixtureMcpFailure::ConnectionMismatch);
    }
    if active.generation != capability.generation {
        return Err(FixtureMcpFailure::GenerationMismatch);
    }
    if state
        .effects
        .keys()
        .any(|key| key.invocation_id == capability.invocation_id)
    {
        return Err(FixtureMcpFailure::InvocationConflict);
    }
    Ok(())
}

fn map_phase_outcome(
    state: &Arc<Mutex<FixtureState>>,
    capability: &mut FixtureCallCapability,
    outcome: ProcessPhaseOutcome,
) -> Result<FixtureCallResult, FixtureMcpFailure> {
    match outcome {
        ProcessPhaseOutcome::PreEffectDenied {
            failure,
            receipt,
            payload,
        } => {
            capability.restore_process_payload(*payload);
            refund_process(state, receipt, refund_reason(failure))
                .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
            Err(failure_error(failure))
        }
        ProcessPhaseOutcome::EffectCompleted { receipt } => Ok(receipt.result()),
        ProcessPhaseOutcome::EffectUncertain { receipt, reason } => {
            if receipt.result() != FixtureCallResult::Uncertain {
                return Err(FixtureMcpFailure::InvalidStateTransition);
            }
            match reason {
                ProcessUncertainReason::Denied
                | ProcessUncertainReason::Executor
                | ProcessUncertainReason::Host
                | ProcessUncertainReason::Lifecycle
                | ProcessUncertainReason::Cleanup
                | ProcessUncertainReason::Pending
                | ProcessUncertainReason::Ledger
                | ProcessUncertainReason::State => Err(FixtureMcpFailure::DispatchUncertain),
            }
        }
        ProcessPhaseOutcome::StateUnavailableAfterAdmission => {
            Err(FixtureMcpFailure::InvalidStateTransition)
        }
    }
}

fn refund_reason(failure: ProcessPreEffectFailure) -> ProcessRefundReason {
    match failure {
        ProcessPreEffectFailure::Authorization => ProcessRefundReason::Authorization,
        ProcessPreEffectFailure::Containment => ProcessRefundReason::Containment,
        #[cfg(test)]
        ProcessPreEffectFailure::Budget => ProcessRefundReason::Budget,
        ProcessPreEffectFailure::GatewayUnavailable => ProcessRefundReason::GatewayUnavailable,
        ProcessPreEffectFailure::CapabilityPreflight => ProcessRefundReason::CapabilityPreflight,
    }
}

fn failure_error(failure: ProcessPreEffectFailure) -> FixtureMcpFailure {
    match failure {
        ProcessPreEffectFailure::Authorization | ProcessPreEffectFailure::CapabilityPreflight => {
            FixtureMcpFailure::ProcessCapabilityInvalid
        }
        ProcessPreEffectFailure::Containment | ProcessPreEffectFailure::GatewayUnavailable => {
            FixtureMcpFailure::ProcessSandboxUnavailable
        }
        #[cfg(test)]
        ProcessPreEffectFailure::Budget => FixtureMcpFailure::AccountingDenied,
    }
}

fn map_gateway_error(error: McpProcessGatewayError) -> FixtureMcpFailure {
    match error {
        McpProcessGatewayError::ExecutionClassMismatch => FixtureMcpFailure::ExecutionClassMismatch,
        McpProcessGatewayError::ProcessIntentRequired => FixtureMcpFailure::ProcessIntentRequired,
        McpProcessGatewayError::ProcessIntentMismatch | McpProcessGatewayError::InvalidBinding => {
            FixtureMcpFailure::ProcessCapabilityInvalid
        }
        McpProcessGatewayError::StaleGeneration => FixtureMcpFailure::GenerationMismatch,
    }
}
