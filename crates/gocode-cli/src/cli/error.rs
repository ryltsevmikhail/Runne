#[derive(Debug)]
enum CliError {
    Usage,
    Profile,
    ProfileIncompatible,
    Runtime,
    Api(RuntimeApiError),
    CredentialInput,
    CredentialOperation,
    UnsupportedCredentialBackend,
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
    #[cfg_attr(not(any(test, target_os = "macos")), expect(dead_code, reason = "mutation store failures are macOS-only"))]
    AuthorityStoreUnavailable,
    #[cfg_attr(not(any(test, target_os = "macos")), expect(dead_code, reason = "publication is macOS-only"))]
    AuthorityArtifactExists,
    #[cfg_attr(not(any(test, target_os = "macos")), expect(dead_code, reason = "publication is macOS-only"))]
    AuthorityArtifactIo,
    AuthorityVerifyFailed,
    #[cfg_attr(not(any(test, target_os = "macos")), expect(dead_code, reason = "trust reset is macOS-only"))]
    AuthorityTrustResetRebootstrapRequired,
}

impl CliError {
    const fn exit_code(&self) -> i32 {
        if matches!(self, Self::Usage | Self::AuthorityUsage) {
            2
        } else {
            1
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
