//! Strict authenticated HTTP projection of canonical Conversation messages.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use runne_api::{
    ApiActor, CanonicalConversationMessage, CanonicalMessageText, CanonicalMessageTextError,
    ConversationCommandContext, ConversationCommandHostPort, ConversationContextScope,
    ConversationCreatedAck, ConversationHostError, ConversationMessagesSnapshot,
    ConversationQueryHostPort, ConversationTextResult, CreateCanonicalConversationCommand,
    GenerateConversationTextCommand, max_message_text_bytes,
};
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::auth::AuthenticatedPrincipal;
use crate::error::{RequestId, canonical_error_response};

const MAX_CONVERSATION_BODY_BYTES: usize = max_message_text_bytes() + 4 * 1024;

/// Shared state for canonical Conversation HTTP handlers.
pub struct ConversationHttpState<H> {
    host: Arc<H>,
    actor: ApiActor,
}

impl<H> Clone for ConversationHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            actor: self.actor.clone(),
        }
    }
}

impl<H> ConversationHttpState<H> {
    /// Wraps the canonical host and fixes the event actor for this adapter.
    pub fn new(host: H, actor: ApiActor) -> Self {
        Self {
            host: Arc::new(host),
            actor,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateConversationBody {
    conversation_id: String,
    workspace_id: String,
    scope: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerateTextBody {
    expected_version: u64,
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationCreatedWire {
    conversation_id: String,
    workspace_id: String,
    stream_version: u64,
    committed_at: i64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationMessageWire {
    message_id: String,
    role: &'static str,
    task_run_id: String,
    attempt_id: String,
    text: String,
    committed_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationTextResultWire {
    conversation_id: String,
    task_run_id: String,
    attempt_id: String,
    conversation_stream_version: u64,
    task_run_stream_version: u64,
    user_message: ConversationMessageWire,
    assistant_message: ConversationMessageWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationMessagesWire {
    conversation_id: String,
    stream_version: u64,
    messages: Vec<ConversationMessageWire>,
}

/// Builds the canonical Conversation create/message route set.
pub fn conversation_router<H>(state: ConversationHttpState<H>) -> Router
where
    H: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
{
    Router::new()
        .route("/v1/conversations", post(create_conversation::<H>))
        .route(
            "/v1/conversations/{conversation_id}/messages",
            post(generate_text::<H>).get(list_messages::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_CONVERSATION_BODY_BYTES))
        .with_state(state)
}

async fn create_conversation<H>(
    State(state): State<ConversationHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Json<CreateConversationBody>, JsonRejection>,
) -> Response
where
    H: ConversationCommandHostPort + ConversationQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let conversation_id = match body.conversation_id.parse::<ConversationId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_conversation_id", &request_id),
    };
    let workspace_id = match body.workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_workspace_id", &request_id),
    };
    let scope = match ConversationContextScope::parse(&body.scope) {
        Some(scope) => scope,
        None => return bad_request("invalid_conversation_scope", &request_id),
    };

    match state
        .host
        .create_conversation(
            context,
            CreateCanonicalConversationCommand {
                conversation_id,
                workspace_id,
                scope,
            },
        )
        .await
    {
        Ok(ack) => (
            StatusCode::ACCEPTED,
            Json(conversation_created_to_wire(ack)),
        )
            .into_response(),
        Err(error) => host_error_response(error, &request_id),
    }
}

async fn generate_text<H>(
    State(state): State<ConversationHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<GenerateTextBody>, JsonRejection>,
) -> Response
where
    H: ConversationCommandHostPort + ConversationQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let conversation_id = match conversation_id.parse::<ConversationId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_conversation_id", &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let text = match CanonicalMessageText::new(body.text) {
        Ok(value) => value,
        Err(CanonicalMessageTextError::Empty) => {
            return bad_request("message_text_empty", &request_id);
        }
        Err(CanonicalMessageTextError::TooLarge { .. }) => {
            return bad_request("message_text_too_large", &request_id);
        }
    };

    match state
        .host
        .generate_text(
            context,
            GenerateConversationTextCommand {
                conversation_id,
                expected_version: body.expected_version,
                text,
            },
        )
        .await
    {
        Ok(result) => (StatusCode::OK, Json(text_result_to_wire(result))).into_response(),
        Err(error) => host_error_response(error, &request_id),
    }
}

async fn list_messages<H>(
    State(state): State<ConversationHttpState<H>>,
    Extension(request_id): Extension<RequestId>,
    Path(conversation_id): Path<String>,
) -> Response
where
    H: ConversationCommandHostPort + ConversationQueryHostPort,
{
    let conversation_id = match conversation_id.parse::<ConversationId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_conversation_id", &request_id),
    };
    match state.host.list_messages(conversation_id).await {
        Ok(snapshot) => (StatusCode::OK, Json(messages_to_wire(snapshot))).into_response(),
        Err(error) => host_error_response(error, &request_id),
    }
}

include!("conversations/helpers.rs");
