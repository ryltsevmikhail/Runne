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
}

impl OutputFormat {
    /// Parses format from string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            _ => None,
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
    CredentialInputInvalid,
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
            Self::CredentialInputInvalid
            | Self::CredentialOperationFailed
            | Self::CredentialBackendUnsupported => 4,
        }
    }
}
