use super::super::{
    process_call::{ProcessDispatchPayload, ProcessEffectKey},
    runtime::FixtureMcpRuntime,
};
use super::{McpProcessGatewayError, McpProcessToolGateway};
use crate::fixture::runtime::process_ledger::ProcessPhaseOutcome;
use crate::fixture::runtime::process_ledger::ProcessReserveOutcome;

#[derive(Debug, PartialEq, Eq)]
pub(in crate::fixture) enum TestDispatchError {
    Gateway(McpProcessGatewayError),
    Busy,
    InvocationConflict,
    TerminalReplay,
    ReservationUnavailable,
}

pub(super) fn dispatch_for_test(
    gateway: &McpProcessToolGateway,
    runtime: &FixtureMcpRuntime,
    key: ProcessEffectKey,
    payload: ProcessDispatchPayload,
) -> Result<ProcessPhaseOutcome, TestDispatchError> {
    let receipt = match runtime
        .reserve_process(key)
        .map_err(|_| TestDispatchError::ReservationUnavailable)?
    {
        ProcessReserveOutcome::Owner(receipt) => receipt,
        ProcessReserveOutcome::BusyReserved => return Err(TestDispatchError::Busy),
        ProcessReserveOutcome::InvocationConflict => {
            return Err(TestDispatchError::InvocationConflict);
        }
        ProcessReserveOutcome::TerminalReplay(_) => return Err(TestDispatchError::TerminalReplay),
    };
    let verified =
        McpProcessToolGateway::verify_c2b(&payload).map_err(TestDispatchError::Gateway)?;
    let claimed = gateway
        .claim_verified(verified)
        .map_err(TestDispatchError::Gateway)?;
    Ok(gateway.dispatch_claimed(claimed, receipt, payload))
}

pub(super) fn dispatch_reserved_for_test(
    gateway: &McpProcessToolGateway,
    receipt: crate::fixture::runtime::process_ledger::ProcessReservationReceipt,
    payload: ProcessDispatchPayload,
) -> Result<ProcessPhaseOutcome, TestDispatchError> {
    let verified =
        McpProcessToolGateway::verify_c2b(&payload).map_err(TestDispatchError::Gateway)?;
    let claimed = gateway
        .claim_verified(verified)
        .map_err(TestDispatchError::Gateway)?;
    Ok(gateway.dispatch_claimed(claimed, receipt, payload))
}
