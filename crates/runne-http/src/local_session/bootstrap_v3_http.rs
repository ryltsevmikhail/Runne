use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_application::local_session::{
    BOOTSTRAP_KEY_VERSION_V3, BOOTSTRAP_WIRE_VERSION_V3, BootstrapPreallocationProof,
    BootstrapProof, LocalSessionChallengeId, LocalSessionError,
};
use serde::{Deserialize, Serialize};

use super::{LocalSessionHttpState, decode_16, decode_32, rejected};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PreallocationRequest {
    wire_version: String,
    key_version: u16,
    client_nonce: String,
    not_before: String,
    expiry: String,
    preallocation_proof: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreallocationResponse {
    wire_version: &'static str,
    key_version: u16,
    challenge_id: String,
    server_nonce: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct FinalRequest {
    wire_version: String,
    key_version: u16,
    challenge_id: String,
    final_proof: String,
    authority: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinalResponse {
    wire_version: &'static str,
    key_version: u16,
    expires_at_monotonic_millis: u64,
    session_id: String,
}

pub(super) async fn challenge(
    State(state): State<LocalSessionHttpState>,
    body: Result<Json<PreallocationRequest>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return rejected(),
    };
    let (Some(client_nonce), Some(proof), Some(now)) = (
        decode_32(&body.client_nonce),
        decode_32(&body.preallocation_proof),
        (state.clock)(),
    ) else {
        return rejected();
    };
    if body.wire_version != BOOTSTRAP_WIRE_VERSION_V3
        || body.key_version != BOOTSTRAP_KEY_VERSION_V3
    {
        return rejected();
    }
    let result = state
        .service
        .lock()
        .map_err(|_| LocalSessionError::Unavailable)
        .and_then(|mut service| {
            service.preallocate(
                BootstrapPreallocationProof {
                    key_version: body.key_version,
                    client_nonce,
                    not_before_rfc3339_utc_microseconds: body.not_before,
                    expiry_rfc3339_utc_microseconds: body.expiry,
                    proof: BootstrapProof::new(proof),
                },
                now,
            )
        });
    match result {
        Ok(value) => Json(PreallocationResponse {
            wire_version: BOOTSTRAP_WIRE_VERSION_V3,
            key_version: BOOTSTRAP_KEY_VERSION_V3,
            challenge_id: URL_SAFE_NO_PAD.encode(value.id.0),
            server_nonce: URL_SAFE_NO_PAD.encode(value.server_nonce),
        })
        .into_response(),
        Err(_) => rejected(),
    }
}

pub(super) async fn authenticate(
    State(state): State<LocalSessionHttpState>,
    body: Result<Json<FinalRequest>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return rejected(),
    };
    let (Some(id), Some(proof), Some(authority), Some(now)) = (
        decode_16(&body.challenge_id),
        decode_32(&body.final_proof),
        decode_32(&body.authority),
        (state.clock)(),
    ) else {
        return rejected();
    };
    if body.wire_version != BOOTSTRAP_WIRE_VERSION_V3
        || body.key_version != BOOTSTRAP_KEY_VERSION_V3
    {
        return rejected();
    }
    let result = state
        .service
        .lock()
        .map_err(|_| LocalSessionError::Unavailable)
        .and_then(|mut service| {
            service.consume_final(
                LocalSessionChallengeId(id),
                BootstrapProof::new(proof),
                authority,
                now,
            )
        });
    match result {
        Ok(value) => Json(FinalResponse {
            wire_version: BOOTSTRAP_WIRE_VERSION_V3,
            key_version: BOOTSTRAP_KEY_VERSION_V3,
            expires_at_monotonic_millis: u64::try_from(value.expires_at_monotonic.as_millis())
                .unwrap_or(u64::MAX),
            session_id: hex::encode(value.binding.ephemeral().session_id()),
        })
        .into_response(),
        Err(_) => rejected(),
    }
}
