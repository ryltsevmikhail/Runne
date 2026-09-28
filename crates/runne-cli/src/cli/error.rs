/// CLI error types with associated exit codes and error codes.
///
/// Exit code contract:
/// - 0: Success (including help/version)
/// - 1: Runtime/API error
/// - 2: Usage error (invalid args, unknown command)
/// - 3: Profile error (unavailable, incompatible)
/// - 4: Credential error (operation, unsupported backend)
#[derive(Debug)]
enum CliError {
    Help(String),
    Version(String),
    Usage,
    UnknownCommand(String),
    Profile,
    ProfileIncompatible,
    Runtime,
    Api(RuntimeApiError),
    CredentialOperation,
    UnsupportedCredentialBackend,
    HealthNonHealthy(CommandOutput),
    DoctorNonHealthy(CommandOutput),
    /// The task run reached a non-success terminal outcome; the full output
    /// (including the terminal receipt) goes to stdout, exit stays non-zero.
    TaskNonHealthy(CommandOutput),
    /// The bounded wait expired without a terminal outcome; the run stays
    /// uncertain, never reported as success. The observed event stream goes to
    /// stdout while the typed envelope goes to stderr.
    TaskUncertain(CommandOutput),
    /// A cancellation was requested but no terminal outcome arrived within
    /// the grace window; never reported as "cancelled".
    CancelPending(CommandOutput),
    /// No accessible session matches the resume request.
    SessionNotFound,
    /// The session belongs to a different workspace than asserted.
    SessionWorkspaceMismatch,
    AuthorityUsage,
    #[cfg(not(target_os = "macos"))]
    AuthorityUnsupportedPlatform,
    AuthorityGit,
    #[cfg(any(test, target_os = "macos"))]
    AuthorityDirtyWorktree,
    #[cfg(test)]
    AuthorityNonInteractive,
    #[cfg(test)]
    AuthorityConfirmationFailed,
    #[cfg(any(test, target_os = "macos"))]
    AuthorityBackupTamperedOrWrongPassphrase,
    AuthorityUnavailable,
    AuthorityTrustInvalid,
    AuthorityAnchorMismatch,
    #[cfg_attr(not(test), allow(dead_code))]
    AuthorityStoreUnavailable,
    #[cfg_attr(not(test), allow(dead_code))]
    AuthorityArtifactExists,
    #[cfg_attr(not(test), allow(dead_code))]
    AuthorityArtifactIo,
    AuthorityVerifyFailed,
    #[cfg_attr(not(test), allow(dead_code))]
    AuthorityTrustResetRebootstrapRequired,
}

impl CliError {
    const fn exit_code(&self) -> i32 {
        match self {
            Self::Help(_) | Self::Version(_) => 0,
            Self::Usage | Self::UnknownCommand(_) | Self::AuthorityUsage => 2,
            Self::Profile | Self::ProfileIncompatible => 3,
            Self::CredentialOperation | Self::UnsupportedCredentialBackend => 4,
            Self::TaskUncertain(_) | Self::CancelPending(_) => 5,
            _ => 1,
        }
    }

    /// Returns the stable error code for JSON output.
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Help(_) | Self::Version(_) => None,
            Self::Usage | Self::AuthorityUsage => Some(ErrorCode::InvalidArguments),
            Self::UnknownCommand(_) => Some(ErrorCode::UnknownCommand),
            Self::Profile => Some(ErrorCode::ProfileUnavailable),
            Self::ProfileIncompatible => Some(ErrorCode::ProfileIncompatible),
            Self::Runtime | Self::HealthNonHealthy(_) | Self::DoctorNonHealthy(_) => {
                Some(ErrorCode::RuntimeUnavailable)
            }
            Self::CredentialOperation => Some(ErrorCode::CredentialOperationFailed),
            Self::UnsupportedCredentialBackend => Some(ErrorCode::CredentialBackendUnsupported),
            Self::TaskUncertain(_) => Some(ErrorCode::TaskUncertain),
            Self::CancelPending(_) => Some(ErrorCode::CancelPending),
            Self::Api(error) if error.kind() == RuntimeApiErrorKind::ModelMismatch => {
                Some(ErrorCode::ModelMismatch)
            }
            Self::SessionNotFound => Some(ErrorCode::SessionNotFound),
            Self::SessionWorkspaceMismatch => Some(ErrorCode::SessionWorkspaceMismatch),
            _ => Some(ErrorCode::ApiError),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help(text) | Self::Version(text) => formatter.write_str(text),
            Self::Usage => formatter.write_str(USAGE),
            Self::UnknownCommand(name) => write!(formatter, "unknown command: {name}"),
            Self::Profile => formatter.write_str("local runtime profile is unavailable"),
            Self::ProfileIncompatible => {
                formatter.write_str("local runtime profile is incompatible")
            }
            Self::Runtime => formatter.write_str("runtime is unavailable"),
            Self::Api(error) => {
                write!(formatter, "{error}")?;
                if let Some(request_id) = error.request_id() {
                    write!(formatter, " (request {request_id})")?;
                }
                Ok(())
            }
            Self::CredentialOperation => {
                formatter.write_str("provider credential operation failed")
            }
            Self::UnsupportedCredentialBackend => {
                formatter.write_str("provider credential backend is unsupported")
            }
            Self::HealthNonHealthy(_) => formatter.write_str("runtime health check failed"),
            Self::DoctorNonHealthy(_) => formatter.write_str("diagnostics found failing checks"),
            Self::TaskNonHealthy(_) => {
                formatter.write_str("task run reached a non-success terminal outcome")
            }
            Self::TaskUncertain(_) => {
                formatter
                    .write_str("task run did not reach a terminal outcome within the bounded wait")
            }
            Self::CancelPending(_) => formatter.write_str(
                "cancellation was requested but no terminal outcome arrived within the grace window",
            ),
            Self::SessionNotFound => {
                formatter.write_str("no accessible session matches the resume request")
            }
            Self::SessionWorkspaceMismatch => {
                formatter.write_str("session belongs to a different workspace")
            }
            Self::AuthorityUsage => formatter.write_str("USAGE"),
            #[cfg(not(target_os = "macos"))]
            Self::AuthorityUnsupportedPlatform => formatter.write_str("UNSUPPORTED_PLATFORM"),
            Self::AuthorityGit => formatter.write_str("TRUST_INVALID"),
            #[cfg(any(test, target_os = "macos"))]
            Self::AuthorityDirtyWorktree => formatter.write_str("AUTHORITY_DIRTY_WORKTREE"),
            #[cfg(test)]
            Self::AuthorityNonInteractive => formatter.write_str("NONINTERACTIVE"),
            #[cfg(test)]
            Self::AuthorityConfirmationFailed => formatter.write_str("CONFIRMATION_FAILED"),
            #[cfg(any(test, target_os = "macos"))]
            Self::AuthorityBackupTamperedOrWrongPassphrase => {
                formatter.write_str("BACKUP_TAMPERED_OR_WRONG_PASSPHRASE")
            }
            Self::AuthorityUnavailable => formatter.write_str("ARTIFACT_IO"),
            Self::AuthorityTrustInvalid => formatter.write_str("TRUST_INVALID"),
            Self::AuthorityAnchorMismatch => formatter.write_str("ANCHOR_MISMATCH"),
            Self::AuthorityStoreUnavailable => formatter.write_str("STORE_UNAVAILABLE"),
            Self::AuthorityArtifactExists => formatter.write_str("ARTIFACT_EXISTS"),
            Self::AuthorityArtifactIo => formatter.write_str("ARTIFACT_IO"),
            Self::AuthorityVerifyFailed => formatter.write_str("VERIFY_FAILED"),
            Self::AuthorityTrustResetRebootstrapRequired => {
                formatter.write_str("TRUST_RESET_REBOOTSTRAP_REQUIRED")
            }
        }
    }
}
