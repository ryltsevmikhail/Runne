// Output envelope for CLI responses.
//
// JSON schema contract (schemaVersion: 1):
//
// Success:
// {
//   "schemaVersion": 1,
//   "ok": true,
//   "data": { ... }
// }
//
// Error:
// {
//   "schemaVersion": 1,
//   "ok": false,
//   "error": {
//     "code": "error_code",
//     "message": "Human readable message"
//   }
// }

use serde::Serialize;

/// JSON schema version for CLI output.
pub const SCHEMA_VERSION: u32 = 1;

/// Output format selection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Jsonl,
}

impl OutputFormat {
    /// Parses format from string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            "jsonl" => Some(Self::Jsonl),
            _ => None,
        }
    }
}

/// Typed command output produced by one command and rendered exactly once at
/// the process boundary (`render_command_output`).
///
/// The JSON rendering of the [`Self::Text`] variant is the `output` string
/// field of `data` and is reserved for plain (non-JSON) payloads such as
/// identifiers and single-word outcomes. Structured payloads must use
/// [`Self::Typed`] so JSON clients parse `data` directly; pre-serialized JSON
/// as a string payload is forbidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutput {
    /// Plain text payload shared by the text and JSON renderings.
    Text(String),
    /// Human-readable text rendering plus the typed JSON `data` payload.
    Typed {
        text: String,
        data: serde_json::Value,
    },
    /// Streaming line-delimited payload: one JSON object per line under
    /// [`OutputFormat::Jsonl`], a JSON array in `data` under
    /// [`OutputFormat::Json`], joined lines under [`OutputFormat::Text`].
    Jsonl(Vec<serde_json::Value>),
}

impl CommandOutput {
    /// Creates a plain text output.
    #[must_use]
    pub fn text(payload: impl Into<String>) -> Self {
        Self::Text(payload.into())
    }

    /// Creates a typed output with its human-readable text rendering.
    #[must_use]
    pub fn typed(text: impl Into<String>, data: serde_json::Value) -> Self {
        Self::Typed {
            text: text.into(),
            data,
        }
    }

    /// Returns the text-format rendering without the trailing newline.
    #[must_use]
    pub fn render_text(&self) -> String {
        match self {
            Self::Text(text) | Self::Typed { text, .. } => text.clone(),
            Self::Jsonl(lines) => lines
                .iter()
                .map(|line| serde_json::to_string(line).unwrap_or_default())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    /// Returns the typed JSON `data` payload; never a pre-serialized JSON string.
    #[must_use]
    pub fn data_value(&self) -> serde_json::Value {
        match self {
            Self::Text(text) => serde_json::json!({ "output": text }),
            Self::Typed { data, .. } => data.clone(),
            Self::Jsonl(lines) => serde_json::Value::Array(lines.clone()),
        }
    }
}

/// Successful response envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessEnvelope<T> {
    pub schema_version: u32,
    pub ok: bool,
    pub data: T,
}

impl<T: Serialize> SuccessEnvelope<T> {
    /// Creates a new success envelope.
    #[must_use]
    pub const fn new(data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ok: true,
            data,
        }
    }
}

/// Error response envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorEnvelope {
    pub schema_version: u32,
    pub ok: bool,
    pub error: ErrorDetail,
}

impl ErrorEnvelope {
    /// Creates a new error envelope.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ok: false,
            error: ErrorDetail {
                code,
                message: message.into(),
            },
        }
    }
}

/// Error detail with stable code and message.
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
}

/// Stable error codes for JSON output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // Usage errors (exit 2)
    InvalidArguments,
    UnknownCommand,

    // Profile errors (exit 3)
    ProfileUnavailable,
    ProfileIncompatible,

    // Runtime errors (exit 1)
    RuntimeUnavailable,
    ApiError,

    // Credential errors (exit 4)
    CredentialOperationFailed,
    CredentialBackendUnsupported,
}

impl ErrorCode {
    /// Returns the exit code for this error.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::InvalidArguments | Self::UnknownCommand => 2,
            Self::ProfileUnavailable | Self::ProfileIncompatible => 3,
            Self::RuntimeUnavailable | Self::ApiError => 1,
            Self::CredentialOperationFailed | Self::CredentialBackendUnsupported => 4,
        }
    }
}
