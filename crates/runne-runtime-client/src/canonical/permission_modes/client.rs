use super::validate::{ExpectedChange, decode_command_status, decode_status};
use crate::canonical::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, RuntimeApiError, RuntimeApiErrorKind,
    read_bounded,
};
use reqwest::{Response, header::CONTENT_TYPE};
use runne_api::{
    PermissionModeChangeRequestV1, PermissionModeCommandStatusV2, PermissionModeStatusV1,
};
use serde::Deserialize;

impl AuthenticatedRuntimeClient {
    /// Reads the runtime's current selected/effective permission-mode projection.
    ///
    /// # Errors
    /// Returns a typed transport error or `InvalidResponse` for an incoherent projection.
    pub async fn permission_mode_status(
        &self,
        workspace_id: CanonicalId,
    ) -> Result<PermissionModeStatusV1, RuntimeApiError> {
        let path = format!("/v2/workspaces/{workspace_id}/permission-mode");
        let response = self
            .authenticated_request(self.http_client().get(self.url(&path)))?
            .send()
            .await
            .map_err(|_| unavailable())?;
        let body = read_status_response(response).await?;
        decode_status(&body)
    }

    /// Sends one caller-intent command; ambiguous replies require command readback.
    ///
    /// # Errors
    /// Returns `UnknownAfterSend` when the response cannot establish the command result.
    pub async fn request_permission_mode_change(
        &self,
        request: PermissionModeChangeRequestV1,
    ) -> Result<PermissionModeCommandStatusV2, RuntimeApiError> {
        let expected = ExpectedChange::from_request(&request)?;
        let command = CommandIdentity::new(expected.command_id, expected.idempotency_key.clone())?;
        let body = serde_json::to_vec(&request).map_err(|_| invalid_request())?;
        let path = format!("/v2/workspaces/{}/permission-mode", expected.workspace_id);
        let response = self
            .command_request(self.http_client().post(self.url(&path)), &command)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| unknown_after_send())?;
        let status = response.status().as_u16();
        let body = if matches!(status, 200 | 202) {
            read_body(response, true).await?
        } else {
            return Err(read_control_error(response, true).await);
        };
        let result = decode_command_status(&body, expected.command_id, Some(&expected))
            .map_err(|_| unknown_after_send())?;
        let expected_status = match result {
            PermissionModeCommandStatusV2::PendingNativeConfirmation { .. }
            | PermissionModeCommandStatusV2::PendingReauthentication { .. } => 202,
            _ => 200,
        };
        (status == expected_status)
            .then_some(result)
            .ok_or_else(unknown_after_send)
    }

    /// Reads one command's durable status after a reconnect or ambiguous POST.
    ///
    /// # Errors
    /// Returns a typed transport error or `InvalidResponse` for mismatched command readback.
    pub async fn permission_mode_command_status(
        &self,
        workspace_id: CanonicalId,
        command_id: CanonicalId,
    ) -> Result<PermissionModeCommandStatusV2, RuntimeApiError> {
        let path = format!("/v2/workspaces/{workspace_id}/permission-mode/commands/{command_id}");
        let response = self
            .authenticated_request(self.http_client().get(self.url(&path)))?
            .send()
            .await
            .map_err(|_| unavailable())?;
        let body = read_status_response(response).await?;
        decode_command_status(&body, command_id, None)
    }
}

async fn read_status_response(response: Response) -> Result<Vec<u8>, RuntimeApiError> {
    if response.status().as_u16() != 200 {
        return Err(read_control_error(response, false).await);
    }
    read_body(response, false).await
}

async fn read_body(response: Response, after_send: bool) -> Result<Vec<u8>, RuntimeApiError> {
    read_bounded(response, super::super::MAXIMUM_CANONICAL_RESPONSE_BYTES)
        .await
        .map_err(|error| {
            if after_send {
                unknown_after_send()
            } else {
                error
            }
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorEnvelope {
    code: String,
    request_id: String,
}

async fn read_control_error(response: Response, after_send: bool) -> RuntimeApiError {
    let status = response.status().as_u16();
    let header_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let result = async {
        let body = read_bounded(response, super::super::MAXIMUM_ERROR_RESPONSE_BYTES).await?;
        let envelope: ErrorEnvelope = serde_json::from_slice(&body)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        if CanonicalId::parse(&envelope.request_id).is_err()
            || header_id.as_deref() != Some(envelope.request_id.as_str())
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        let kind = match (status, envelope.code.as_str()) {
            (
                400,
                "invalid_permission_mode_request"
                | "permission_mode_invariant_violation"
                | "permission_mode_preset_unsupported",
            ) => RuntimeApiErrorKind::InvalidRequest,
            (401, "unauthorized") => RuntimeApiErrorKind::Unauthorized,
            (403, "permission_mode_policy_denied") => RuntimeApiErrorKind::ManagedPolicy,
            (404, "permission_mode_not_found") => RuntimeApiErrorKind::NotFound,
            (
                409,
                "permission_mode_conflict"
                | "permission_mode_idempotency_conflict"
                | "permission_mode_stale_revision"
                | "permission_mode_expired"
                | "permission_mode_cancelled"
                | "permission_mode_reconciliation_required",
            ) => RuntimeApiErrorKind::Conflict,
            (
                503,
                "permission_mode_native_authority_unavailable"
                | "permission_mode_enforcement_unavailable"
                | "permission_mode_scope_unenforceable"
                | "permission_mode_unavailable",
            ) => RuntimeApiErrorKind::Unavailable,
            _ => RuntimeApiErrorKind::InvalidResponse,
        };
        Err(RuntimeApiError::new(kind))
    }
    .await;
    match result {
        Err(error)
            if after_send
                && matches!(
                    error.kind(),
                    RuntimeApiErrorKind::Unavailable
                        | RuntimeApiErrorKind::InvalidResponse
                        | RuntimeApiErrorKind::ResponseTooLarge
                ) =>
        {
            unknown_after_send()
        }
        Err(error) => error,
        Ok(()) => RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse),
    }
}

const fn invalid_request() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest)
}

const fn unavailable() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)
}

const fn unknown_after_send() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::UnknownAfterSend)
}
