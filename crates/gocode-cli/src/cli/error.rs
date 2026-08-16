/// CLI error types with associated exit codes and error codes.
///
/// Exit code contract:
/// - 0: Success (including help/version)
/// - 1: Runtime/API error
/// - 2: Usage error (invalid args, unknown command)
/// - 3: Profile error (unavailable, incompatible)
/// - 4: Credential error (input, operation, unsupported backend)
#[derive(Debug)]
enum CliError {
    Help(String),
    Version(String),
    Usage,
    Profile,
    ProfileIncompatible,
    Runtime,
    Api(RuntimeApiError),
    CredentialInput,
    CredentialOperation,
    UnsupportedCredentialBackend,
    HealthNonHealthy(String),
    AuthorityUsage,
    #[cfg(not(target_os = "macos"))]
    AuthorityUnsupportedPlatform,
    AuthorityGit,
    #[cfg(any(test, target_os = "macos"))]
    #[cfg_attr(all(target_os = "macos", not(test)), expect(dead_code, reason = "constructed only by the intentionally un-wired macOS authority lifecycle"))]
    AuthorityDirtyWorktree,
    #[cfg(test)]
    AuthorityNonInteractive,
    #[cfg(test)]
    AuthorityConfirmationFailed,
    #[cfg(any(test, target_os = "macos"))]
    #[cfg_attr(all(target_os = "macos", not(test)), expect(dead_code, reason = "constructed only by the intentionally un-wired macOS authority lifecycle"))]
    AuthorityBackupTamperedOrWrongPassphrase,
    AuthorityUnavailable,
    AuthorityTrustInvalid,
    AuthorityAnchorMismatch,
    #[cfg_attr(not(test), expect(dead_code, reason = "mutation store failures are macOS-only"))]
    AuthorityStoreUnavailable,
    #[cfg_attr(not(test), expect(dead_code, reason = "publication is macOS-only"))]
    AuthorityArtifactExists,
    #[cfg_attr(not(test), expect(dead_code, reason = "publication is macOS-only"))]
    AuthorityArtifactIo,
    AuthorityVerifyFailed,
    #[cfg_attr(not(test), expect(dead_code, reason = "trust reset is macOS-only"))]
    AuthorityTrustResetRebootstrapRequired,
}

impl CliError {
    const fn exit_code(&self) -> i32 {
        match self {
            Self::Help(_) | Self::Version(_) => 0,
            Self::Usage | Self::AuthorityUsage => 2,
            Self::Profile | Self::ProfileIncompatible => 3,
            Self::CredentialInput
            | Self::CredentialOperation
            | Self::UnsupportedCredentialBackend => 4,
            _ => 1,
        }
    }

    /// Returns the stable error code for JSON output.
    const fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Help(_) | Self::Version(_) => None,
            Self::Usage | Self::AuthorityUsage => Some(ErrorCode::InvalidArguments),
            Self::Profile => Some(ErrorCode::ProfileUnavailable),
            Self::ProfileIncompatible => Some(ErrorCode::ProfileIncompatible),
            Self::Runtime | Self::HealthNonHealthy(_) => Some(ErrorCode::RuntimeUnavailable),
            Self::CredentialInput => Some(ErrorCode::CredentialInputInvalid),
            Self::CredentialOperation => Some(ErrorCode::CredentialOperationFailed),
            Self::UnsupportedCredentialBackend => Some(ErrorCode::CredentialBackendUnsupported),
            _ => Some(ErrorCode::ApiError),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help(text) | Self::Version(text) => formatter.write_str(text),
            Self::Usage => formatter.write_str(USAGE),
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
            Self::CredentialInput => formatter.write_str("provider credential input is invalid"),
            Self::CredentialOperation => formatter.write_str("provider credential operation failed"),
            Self::UnsupportedCredentialBackend => {
                formatter.write_str("provider credential backend is unsupported")
            }
            Self::HealthNonHealthy(_) => formatter.write_str("runtime health check failed"),
            Self::AuthorityUsage => formatter.write_str("USAGE"),
            #[cfg(not(target_os = "macos"))]
            Self::AuthorityUnsupportedPlatform => formatter.write_str("UNSUPPORTED_PLATFORM"),
            Self::AuthorityGit => formatter.write_str("TRUST_INVALID"),
            #[cfg(any(test, target_os = "macos"))]
            Self::AuthorityDirtyWorktree => formatter.write_str("AUTHORITY_DIRTY_WORKTREE"),
            #[cfg(test)]
            Self::AuthorityNonInteractive => formatter.write_str("NONINTERACTIVE"),
            #[cfg(test)]
            Self::AuthorityConfirmationFailed => {
                formatter.write_str("CONFIRMATION_FAILED")
            }
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
