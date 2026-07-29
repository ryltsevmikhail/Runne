const MAX_ID_BYTES: usize = 128;

/// Invalid stable MCP identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidMcpIdentity {
    /// Empty value.
    Empty,
    /// Value exceeds the trusted bound.
    TooLong,
    /// Value is not printable ASCII.
    InvalidCharacter,
}

macro_rules! bounded_id {
    ($name:ident, $docs:literal) => {
        #[doc = $docs]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);
        impl $name {
            /// Creates a bounded printable ASCII identity.
            pub fn new(value: impl Into<String>) -> Result<Self, InvalidMcpIdentity> {
                let value = value.into();
                if value.is_empty() {
                    return Err(InvalidMcpIdentity::Empty);
                }
                if value.len() > MAX_ID_BYTES {
                    return Err(InvalidMcpIdentity::TooLong);
                }
                if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
                    return Err(InvalidMcpIdentity::InvalidCharacter);
                }
                Ok(Self(value))
            }
            /// Returns the identity text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

bounded_id!(McpServerId, "Stable MCP server identity.");
bounded_id!(McpRuntimeInstanceId, "TaskRun-local MCP runtime identity.");
bounded_id!(McpConnectionId, "Generation-bound MCP connection identity.");
bounded_id!(McpSessionId, "Transient MCP session identity.");
bounded_id!(McpInvocationId, "Single MCP tool invocation identity.");

/// Project-owned transient JSON-RPC request identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum McpRequestId {
    /// Non-negative integral ID.
    Number(u64),
    /// Bounded string ID.
    String(String),
}

/// Project-owned normalized JSON-RPC message.
#[derive(Clone, PartialEq)]
pub struct McpNormalizedMessage {
    pub(crate) request_id: Option<McpRequestId>,
    pub(crate) method: Option<String>,
    pub(crate) params: Option<serde_json::Value>,
    pub(crate) result: Option<serde_json::Value>,
    pub(crate) error_code: Option<i64>,
}

impl core::fmt::Debug for McpNormalizedMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("McpNormalizedMessage")
            .field("has_request_id", &self.request_id.is_some())
            .field("method", &self.method)
            .field("has_params", &self.params.is_some())
            .field("has_result", &self.result.is_some())
            .field("error_code", &self.error_code)
            .finish()
    }
}

impl McpNormalizedMessage {
    pub(crate) fn request(
        request_id: Option<McpRequestId>,
        method: String,
        params: serde_json::Value,
    ) -> Self {
        Self {
            request_id,
            method: Some(method),
            params: Some(params),
            result: None,
            error_code: None,
        }
    }

    pub(crate) fn success(request_id: McpRequestId, result: serde_json::Value) -> Self {
        Self {
            request_id: Some(request_id),
            method: None,
            params: None,
            result: Some(result),
            error_code: None,
        }
    }

    /// Optional request identity.
    pub const fn request_id(&self) -> Option<&McpRequestId> {
        self.request_id.as_ref()
    }
    /// Request or notification method.
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }
    /// Successful response marker.
    pub const fn is_success_response(&self) -> bool {
        self.request_id.is_some() && self.result.is_some()
    }
    /// Sensitivity-safe error code.
    pub const fn error_code(&self) -> Option<i64> {
        self.error_code
    }
    /// Adapter-local normalized params.
    pub const fn params(&self) -> Option<&serde_json::Value> {
        self.params.as_ref()
    }
    /// Adapter-local normalized successful result.
    pub const fn result(&self) -> Option<&serde_json::Value> {
        self.result.as_ref()
    }
}
