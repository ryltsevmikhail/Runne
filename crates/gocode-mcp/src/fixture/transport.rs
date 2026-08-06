use std::sync::{Arc, Mutex};

use gocode_tools::{
    EffectAdmission, GateStage, ToolAdmissionDecision, ToolAdmissionError, ToolAdmissionPort,
    ToolDispatchRequest, ToolExecutionHandle, ToolProtocolCloseRequest,
};

use crate::{
    McpClientPort, McpNormalizedMessage, McpProtocolCompletionPort, McpRequestId, McpTransportError,
};

use super::{
    model,
    runtime::{FixtureProtocolReservation, FixtureState},
};

pub(super) struct FixtureAdmission;

impl ToolAdmissionPort for FixtureAdmission {
    fn check(
        &self,
        stage: GateStage,
        request: &ToolDispatchRequest,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        Ok(if stage == GateStage::EffectAdmission {
            ToolAdmissionDecision::Winner(EffectAdmission {
                permit_id: request.invocation_id.clone(),
            })
        } else {
            ToolAdmissionDecision::Passed
        })
    }
}

pub(super) struct FixtureClient(pub(super) Arc<Mutex<FixtureState>>);

impl McpClientPort for FixtureClient {
    fn dispatch(&mut self, message: &McpNormalizedMessage) -> Result<(), McpTransportError> {
        let mut state = self.0.lock().map_err(|_| McpTransportError::Unavailable)?;
        state.dispatches += 1;
        let Some(McpRequestId::String(invocation)) = message.request_id() else {
            return Ok(());
        };
        let Some(super::model::FixtureStepOutcome::Response(response)) =
            state.selected_outcomes.remove(invocation)
        else {
            return Ok(());
        };
        let reservation = state
            .protocol_reservations
            .get_mut(invocation)
            .ok_or(McpTransportError::Unavailable)?;
        reservation.terminal_digest = Some(model::digest_domain(
            b"GOCODE_MCP_FIXTURE_RESPONSE_V1\0",
            &[
                invocation.as_bytes(),
                &serde_json::to_vec(&response).map_err(|_| McpTransportError::Unavailable)?,
            ],
        ));
        Ok(())
    }

    fn receive(&mut self) -> Result<McpNormalizedMessage, McpTransportError> {
        Err(McpTransportError::Unavailable)
    }
}

impl McpProtocolCompletionPort for FixtureClient {
    fn reserve_protocol_completion(
        &mut self,
        request: &ToolDispatchRequest,
        admission: &EffectAdmission,
        handle: &ToolExecutionHandle,
    ) -> Result<(), McpTransportError> {
        if admission.permit_id.is_empty() {
            return Err(McpTransportError::Unavailable);
        }
        let mut state = self.0.lock().map_err(|_| McpTransportError::Unavailable)?;
        let active = state
            .active
            .as_ref()
            .ok_or(McpTransportError::Unavailable)?;
        let reservation = FixtureProtocolReservation {
            request_digest: request.request_digest,
            permit_id: admission.permit_id.clone(),
            handle: handle.clone(),
            connection_id: active.connection_id.as_str().to_owned(),
            generation: active.generation,
            terminal_digest: None,
            settled: false,
        };
        match state.protocol_reservations.get(&request.invocation_id) {
            Some(existing)
                if existing.request_digest != reservation.request_digest
                    || existing.permit_id != reservation.permit_id
                    || existing.handle != reservation.handle
                    || existing.connection_id != reservation.connection_id
                    || existing.generation != reservation.generation =>
            {
                Err(McpTransportError::Unavailable)
            }
            Some(_) => Ok(()),
            None => {
                state
                    .protocol_reservations
                    .insert(request.invocation_id.clone(), reservation);
                Ok(())
            }
        }
    }

    fn confirm_protocol_completion(
        &mut self,
        request: &ToolProtocolCloseRequest,
    ) -> Result<(), McpTransportError> {
        let mut state = self.0.lock().map_err(|_| McpTransportError::Unavailable)?;
        let reservation = state
            .protocol_reservations
            .get_mut(&request.invocation_id)
            .ok_or(McpTransportError::Unavailable)?;
        if reservation.request_digest != request.request_digest
            || reservation.handle != request.handle
            || reservation.terminal_digest.is_none()
            || reservation.settled
        {
            return Err(McpTransportError::Unavailable);
        }
        reservation.settled = true;
        Ok(())
    }
}
