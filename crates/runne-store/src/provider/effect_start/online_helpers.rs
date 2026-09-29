// Error mappers and hex encoding for the online effect-start path,
// split from online.rs for the file-length limit.

use runne_application::provider::ProviderAdmissionError;

pub(super) const ONLINE_BINDING_STALE_TRIGGER: &str =
    "online credential effect binding is stale or fenced";
use runne_provider::CredentialLifecycleError;
use rusqlite::{Error as SqliteError, ErrorCode};

pub(super) fn online_clock_error(error: CredentialLifecycleError) -> ProviderAdmissionError {
    match error {
        CredentialLifecycleError::StaleLease => ProviderAdmissionError::AuthorityDenied,
        _ => ProviderAdmissionError::RepositoryFailure,
    }
}

pub(super) fn online_sql_error(error: SqliteError) -> ProviderAdmissionError {
    match error {
        SqliteError::SqliteFailure(code, Some(message))
            if code.code == ErrorCode::ConstraintViolation
                && message == ONLINE_BINDING_STALE_TRIGGER =>
        {
            ProviderAdmissionError::AuthorityDenied
        }
        _ => ProviderAdmissionError::RepositoryFailure,
    }
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
