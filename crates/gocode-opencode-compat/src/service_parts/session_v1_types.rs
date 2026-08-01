/// Canonical, provider-neutral prompt accepted by the V3 compatibility port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPrompt {
    pub session_id: String,
    pub message_id: Option<String>,
    pub text_parts: Vec<String>,
}

/// Canonical host result for a synchronous prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalPromptResult {
    pub session_id: String,
    pub response: serde_json::Value,
}

/// Canonical status values that preserve the pinned OpenCode V1 read model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalSessionStatus {
    Idle,
    Busy,
    Retry {
        attempt: u64,
        message: String,
        next: u64,
    },
}

/// Runtime boundary consumed by the OpenCode V1 compatibility service.
pub trait SessionV1HostPort: Send + Sync {
    fn prompt(
        &self,
        input: CanonicalPrompt,
    ) -> impl std::future::Future<
        Output = Result<CanonicalPromptResult, crate::error::SessionV1HostError>,
    > + Send;

    fn prompt_async(
        &self,
        input: CanonicalPrompt,
    ) -> impl std::future::Future<Output = Result<(), crate::error::SessionV1HostError>> + Send;

    fn status(
        &self,
    ) -> impl std::future::Future<
        Output = Result<Vec<(String, CanonicalSessionStatus)>, crate::error::SessionV1HostError>,
    > + Send;

    fn abort(
        &self,
        session_id: String,
    ) -> impl std::future::Future<Output = Result<bool, crate::error::SessionV1HostError>> + Send;
}

/// Strict compatibility boundary for the four V3 OpenCode V1 session routes.
pub struct OpenCodeSessionV1Service<H: SessionV1HostPort> {
    host: H,
    prompt_response_schema: Arc<JSONSchema>,
}
