//! Authenticated canonical command/query transport.

use std::fmt;
use std::sync::Arc;

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::{EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH, HttpRuntimeClient};

const MAXIMUM_CANONICAL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_ERROR_RESPONSE_BYTES: usize = 8 * 1024;
const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAXIMUM_MESSAGE_TEXT_BYTES: usize = 64 * 1024;

/// Exact command/query capabilities required by this client build.
///
/// Ordering is canonical and part of the authenticated profile response.
pub const REQUIRED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
];

/// Strict `UUIDv7` identity used by the canonical client contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalId(uuid::Uuid);

impl CanonicalId {
    /// Parses an RFC 9562 `UUIDv7` identity.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` for malformed, non-v7, or non-RFC identities.
    pub fn parse(value: &str) -> Result<Self, RuntimeApiError> {
        let parsed = uuid::Uuid::parse_str(value)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        if parsed.get_version_num() != 7 || parsed.get_variant() != uuid::Variant::RFC4122 {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        }
        Ok(Self(parsed))
    }

    /// Generates a fresh `UUIDv7` identity.
    #[must_use]
    pub fn now_v7() -> Self {
        Self(uuid::Uuid::now_v7())
    }
}

impl fmt::Display for CanonicalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for CanonicalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CanonicalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Command identity and opaque idempotency key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandIdentity {
    command_id: CanonicalId,
    idempotency_key: String,
}

impl CommandIdentity {
    /// Validates one command identity for use as HTTP headers.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` for an empty, oversized, control-bearing, or
    /// non-header-safe idempotency key.
    pub fn new(
        command_id: CanonicalId,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let idempotency_key = idempotency_key.into();
        if idempotency_key.is_empty()
            || idempotency_key.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES
            || idempotency_key
                .as_bytes()
                .iter()
                .any(|byte| *byte < 0x20 || *byte == 0x7f)
            || HeaderValue::from_str(&idempotency_key).is_err()
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        }
        Ok(Self {
            command_id,
            idempotency_key,
        })
    }
}

/// Host-owned 32-byte daemon credential.
///
/// The type intentionally implements neither `Debug`, `Display`, nor
/// serialization. The bytes are zeroized after the final clone is dropped.
#[derive(Clone)]
pub struct RuntimeCredential(Arc<Zeroizing<[u8; 32]>>);

impl RuntimeCredential {
    /// Wraps exact daemon credential bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Arc::new(Zeroizing::new(bytes)))
    }

    fn authorization_header(&self) -> Result<HeaderValue, RuntimeApiError> {
        let mut value = [0_u8; 71];
        value[..7].copy_from_slice(b"Bearer ");
        hex::encode_to_slice(self.0.as_ref(), &mut value[7..])
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let header = HeaderValue::from_bytes(&value)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        value.zeroize();
        header
    }
}

/// Result of the exact authenticated runtime profile handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSessionInfo {
    /// Exact selected profile.
    pub profile_id: String,
    /// Exact canonical bundle digest.
    pub schema_hash: String,
    /// Safe runtime build version.
    pub runtime_version: String,
    /// Exact canonical capability set accepted for this session.
    pub capabilities: Vec<String>,
}

/// Authenticated runtime client. Construction is possible only after the
/// exact profile handshake succeeds.
#[derive(Clone)]
pub struct AuthenticatedRuntimeClient {
    client: reqwest::Client,
    endpoint: crate::RuntimeEndpoint,
    credential: RuntimeCredential,
    session: RuntimeSessionInfo,
}

impl AuthenticatedRuntimeClient {
    /// Returns the accepted exact runtime profile.
    #[must_use]
    pub const fn session_info(&self) -> &RuntimeSessionInfo {
        &self.session
    }

    /// Creates one durable Conversation.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn create_conversation(
        &self,
        request: CreateConversationRequest,
    ) -> Result<ConversationCreated, RuntimeApiError> {
        let expected_conversation_id = request.conversation_id;
        let expected_workspace_id = request.workspace_id;
        let url = self.url("/v1/conversations");
        let body = serde_json::to_vec(&CreateConversationWire {
            conversation_id: request.conversation_id,
            workspace_id: request.workspace_id,
        })
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let wire: ConversationCreatedWire = read_success_json(response, &[202]).await?;
        let created = ConversationCreated::from(wire);
        if created.conversation_id != expected_conversation_id
            || created.workspace_id != expected_workspace_id
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(created)
    }

    /// Appends user text and returns the completed durable local generation.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn generate_text(
        &self,
        request: GenerateTextRequest,
    ) -> Result<ConversationTextResult, RuntimeApiError> {
        let expected_conversation_id = request.conversation_id;
        let url = self.url(&format!(
            "/v1/conversations/{}/messages",
            request.conversation_id
        ));
        let body = serde_json::to_vec(&GenerateTextWire {
            expected_version: request.expected_version,
            text: &request.text,
        })
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .command_request(self.client.post(url), &request.identity)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let wire: ConversationTextResultWire = read_success_json(response, &[200]).await?;
        let result = ConversationTextResult::try_from(wire)?;
        if result.conversation_id != expected_conversation_id {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(result)
    }

    /// Reads the authoritative committed Conversation timeline.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn list_messages(
        &self,
        conversation_id: CanonicalId,
    ) -> Result<ConversationMessages, RuntimeApiError> {
        let url = self.url(&format!("/v1/conversations/{conversation_id}/messages"));
        let response = self
            .authenticated_request(self.client.get(url))?
            .send()
            .await
            .map_err(map_transport)?;
        let wire: ConversationMessagesWire = read_success_json(response, &[200]).await?;
        let snapshot = ConversationMessages::try_from(wire)?;
        if snapshot.conversation_id != conversation_id {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(snapshot)
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.endpoint.address(), path)
    }

    fn authenticated_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, RuntimeApiError> {
        Ok(request
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.credential.authorization_header()?))
    }

    fn command_request(
        &self,
        request: reqwest::RequestBuilder,
        identity: &CommandIdentity,
    ) -> Result<reqwest::RequestBuilder, RuntimeApiError> {
        Ok(self
            .authenticated_request(request)?
            .header("x-command-id", identity.command_id.to_string())
            .header("idempotency-key", identity.idempotency_key.as_str()))
    }
}

impl HttpRuntimeClient {
    /// Performs the authenticated exact-profile handshake.
    ///
    /// # Errors
    ///
    /// Returns `Incompatible` unless the daemon confirms the exact accepted
    /// profile and schema digest.
    pub async fn authenticate(
        &self,
        credential: RuntimeCredential,
    ) -> Result<AuthenticatedRuntimeClient, RuntimeApiError> {
        let url = format!("http://{}/v1/runtime/profile", self.endpoint.address());
        let response = self
            .client
            .get(url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, credential.authorization_header()?)
            .send()
            .await
            .map_err(map_transport)?;
        let wire: RuntimeProfileWire = read_success_json(response, &[200]).await?;
        if wire.profile_id != EXPECTED_BUNDLE_ID
            || wire.schema_hash != GOLDEN_BUNDLE_HASH
            || !wire
                .capabilities
                .iter()
                .map(String::as_str)
                .eq(REQUIRED_RUNTIME_CAPABILITIES.iter().copied())
            || wire.runtime_version.is_empty()
            || wire.runtime_version.len() > 64
            || wire.runtime_version.chars().any(char::is_control)
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::Incompatible));
        }
        let session = RuntimeSessionInfo {
            profile_id: wire.profile_id,
            schema_hash: wire.schema_hash,
            runtime_version: wire.runtime_version,
            capabilities: wire.capabilities,
        };
        Ok(AuthenticatedRuntimeClient {
            client: self.client.clone(),
            endpoint: self.endpoint,
            credential,
            session,
        })
    }
}

/// Validated request for creating a Conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateConversationRequest {
    identity: CommandIdentity,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
}

impl CreateConversationRequest {
    /// Creates a typed create request.
    #[must_use]
    pub const fn new(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    ) -> Self {
        Self {
            identity,
            conversation_id,
            workspace_id,
        }
    }
}

/// Validated request for one synchronous text generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateTextRequest {
    identity: CommandIdentity,
    conversation_id: CanonicalId,
    expected_version: u64,
    text: String,
}

impl GenerateTextRequest {
    /// Validates message text against the canonical byte limit.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` for empty or oversized text.
    pub fn new(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        expected_version: u64,
        text: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let text = text.into();
        validate_message_text(&text)?;
        Ok(Self {
            identity,
            conversation_id,
            expected_version,
            text,
        })
    }
}

/// Durable Conversation creation acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationCreated {
    pub conversation_id: CanonicalId,
    pub workspace_id: CanonicalId,
    pub stream_version: u64,
    pub committed_at: u64,
}

/// Closed canonical message role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationMessageRole {
    User,
    Assistant,
}

/// Sanitized durable Conversation message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessage {
    pub message_id: CanonicalId,
    pub role: ConversationMessageRole,
    pub task_run_id: CanonicalId,
    pub attempt_id: CanonicalId,
    pub text: String,
    pub committed_at: u64,
}

/// Completed durable text generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationTextResult {
    pub conversation_id: CanonicalId,
    pub task_run_id: CanonicalId,
    pub attempt_id: CanonicalId,
    pub conversation_stream_version: u64,
    pub task_run_stream_version: u64,
    pub user_message: ConversationMessage,
    pub assistant_message: ConversationMessage,
}

/// Authoritative ordered message snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessages {
    pub conversation_id: CanonicalId,
    pub stream_version: u64,
    pub messages: Vec<ConversationMessage>,
}

/// Stable client failure disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeApiErrorKind {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    Backpressure,
    Unavailable,
    ResponseTooLarge,
    InvalidResponse,
    Incompatible,
}

/// Typed and redacted canonical client failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApiError {
    kind: RuntimeApiErrorKind,
    request_id: Option<String>,
}

impl RuntimeApiError {
    const fn new(kind: RuntimeApiErrorKind) -> Self {
        Self {
            kind,
            request_id: None,
        }
    }

    /// Returns the stable failure disposition.
    #[must_use]
    pub const fn kind(&self) -> RuntimeApiErrorKind {
        self.kind
    }

    /// Returns the safe correlation identity supplied by the daemon.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

impl fmt::Display for RuntimeApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            RuntimeApiErrorKind::InvalidRequest => "runtime request is invalid",
            RuntimeApiErrorKind::Unauthorized => "runtime authentication failed",
            RuntimeApiErrorKind::NotFound => "runtime resource was not found",
            RuntimeApiErrorKind::Conflict => "runtime command conflicted",
            RuntimeApiErrorKind::Backpressure => "runtime is busy",
            RuntimeApiErrorKind::Unavailable => "runtime is unavailable",
            RuntimeApiErrorKind::ResponseTooLarge => "runtime response exceeds the allowed size",
            RuntimeApiErrorKind::InvalidResponse => "runtime response is invalid",
            RuntimeApiErrorKind::Incompatible => "runtime profile is incompatible",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RuntimeApiError {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeProfileWire {
    profile_id: String,
    schema_hash: String,
    runtime_version: String,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateConversationWire {
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateTextWire<'a> {
    expected_version: u64,
    text: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationCreatedWire {
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    stream_version: u64,
    committed_at: u64,
}

impl From<ConversationCreatedWire> for ConversationCreated {
    fn from(wire: ConversationCreatedWire) -> Self {
        Self {
            conversation_id: wire.conversation_id,
            workspace_id: wire.workspace_id,
            stream_version: wire.stream_version,
            committed_at: wire.committed_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConversationMessageRoleWire {
    User,
    Assistant,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationMessageWire {
    message_id: CanonicalId,
    role: ConversationMessageRoleWire,
    task_run_id: CanonicalId,
    attempt_id: CanonicalId,
    text: String,
    committed_at: u64,
}

impl TryFrom<ConversationMessageWire> for ConversationMessage {
    type Error = RuntimeApiError;

    fn try_from(wire: ConversationMessageWire) -> Result<Self, Self::Error> {
        validate_message_text(&wire.text)?;
        Ok(Self {
            message_id: wire.message_id,
            role: match wire.role {
                ConversationMessageRoleWire::User => ConversationMessageRole::User,
                ConversationMessageRoleWire::Assistant => ConversationMessageRole::Assistant,
            },
            task_run_id: wire.task_run_id,
            attempt_id: wire.attempt_id,
            text: wire.text,
            committed_at: wire.committed_at,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationTextResultWire {
    conversation_id: CanonicalId,
    task_run_id: CanonicalId,
    attempt_id: CanonicalId,
    conversation_stream_version: u64,
    task_run_stream_version: u64,
    user_message: ConversationMessageWire,
    assistant_message: ConversationMessageWire,
}

impl TryFrom<ConversationTextResultWire> for ConversationTextResult {
    type Error = RuntimeApiError;

    fn try_from(wire: ConversationTextResultWire) -> Result<Self, Self::Error> {
        let user_message = ConversationMessage::try_from(wire.user_message)?;
        let assistant_message = ConversationMessage::try_from(wire.assistant_message)?;
        if user_message.role != ConversationMessageRole::User
            || assistant_message.role != ConversationMessageRole::Assistant
            || user_message.task_run_id != wire.task_run_id
            || assistant_message.task_run_id != wire.task_run_id
            || user_message.attempt_id != wire.attempt_id
            || assistant_message.attempt_id != wire.attempt_id
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(Self {
            conversation_id: wire.conversation_id,
            task_run_id: wire.task_run_id,
            attempt_id: wire.attempt_id,
            conversation_stream_version: wire.conversation_stream_version,
            task_run_stream_version: wire.task_run_stream_version,
            user_message,
            assistant_message,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationMessagesWire {
    conversation_id: CanonicalId,
    stream_version: u64,
    messages: Vec<ConversationMessageWire>,
}

impl TryFrom<ConversationMessagesWire> for ConversationMessages {
    type Error = RuntimeApiError;

    fn try_from(wire: ConversationMessagesWire) -> Result<Self, Self::Error> {
        let messages = wire
            .messages
            .into_iter()
            .map(ConversationMessage::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            conversation_id: wire.conversation_id,
            stream_version: wire.stream_version,
            messages,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorEnvelope {
    code: String,
    request_id: String,
}

async fn read_success_json<T>(
    response: reqwest::Response,
    expected_statuses: &[u16],
) -> Result<T, RuntimeApiError>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status().as_u16();
    if !expected_statuses.contains(&status) {
        return Err(read_error(response).await);
    }
    let body = read_bounded(response, MAXIMUM_CANONICAL_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body)
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}

async fn read_error(response: reqwest::Response) -> RuntimeApiError {
    let status = response.status().as_u16();
    let body = match read_bounded(response, MAXIMUM_ERROR_RESPONSE_BYTES).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(&body) else {
        return RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse);
    };
    if CanonicalId::parse(&envelope.request_id).is_err() {
        return RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse);
    }
    let kind = match (status, envelope.code.as_str()) {
        (
            400,
            "invalid_request"
            | "invalid_conversation_id"
            | "invalid_workspace_id"
            | "invalid_command_id"
            | "invalid_idempotency_key"
            | "message_text_empty"
            | "message_text_too_large",
        ) => RuntimeApiErrorKind::InvalidRequest,
        (401, "unauthorized") => RuntimeApiErrorKind::Unauthorized,
        (404, "conversation_not_found") => RuntimeApiErrorKind::NotFound,
        (409, "conversation_conflict") => RuntimeApiErrorKind::Conflict,
        (429 | 503, "runtime_backpressure") => RuntimeApiErrorKind::Backpressure,
        (503, "runtime_unavailable") => RuntimeApiErrorKind::Unavailable,
        _ => RuntimeApiErrorKind::InvalidResponse,
    };
    if kind == RuntimeApiErrorKind::InvalidResponse {
        return RuntimeApiError::new(kind);
    }
    RuntimeApiError {
        kind,
        request_id: Some(envelope.request_id),
    }
}

async fn read_bounded(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RuntimeApiError> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(maximum_bytes).unwrap_or(u64::MAX))
    {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::ResponseTooLarge));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_transport)? {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::ResponseTooLarge));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

const fn validate_message_text(text: &str) -> Result<(), RuntimeApiError> {
    if text.is_empty() || text.len() > MAXIMUM_MESSAGE_TEXT_BYTES {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
    }
    Ok(())
}

fn map_transport(_: reqwest::Error) -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)
}
