/// Bounded native-only phase tracker for protected process startup.
#[cfg(unix)]
struct ProtectedLaunchDiagnostic {
    phase: &'static str,
}

#[cfg(unix)]
impl ProtectedLaunchDiagnostic {
    const fn new() -> Self {
        Self {
            phase: "before_spawn",
        }
    }

    const fn at(&mut self, phase: &'static str) {
        self.phase = phase;
    }

    fn report(&self, error: ProtectedBundledRuntimeError) {
        eprintln!(
            "runne-protected-startup phase={} reason={}",
            self.phase,
            protected_launch_failure_code(error)
        );
    }
}

/// Maps native launch failures to a fixed vocabulary without formatting error data.
#[must_use]
pub const fn protected_launch_failure_code(error: ProtectedBundledRuntimeError) -> &'static str {
    match error {
        ProtectedBundledRuntimeError::UnsupportedPlatformBackend => "unsupported_platform",
        ProtectedBundledRuntimeError::ExecutableUnavailable => "executable_unavailable",
        ProtectedBundledRuntimeError::ExecutableIdentityMismatch => "executable_identity",
        ProtectedBundledRuntimeError::RuntimeRootUnavailable => "runtime_root",
        ProtectedBundledRuntimeError::ActivationStateUnavailable => "activation_state",
        ProtectedBundledRuntimeError::ProtectedChannelUnavailable => "protected_channel",
        ProtectedBundledRuntimeError::SpawnFailed => "spawn_failed",
        ProtectedBundledRuntimeError::ReadinessTimeout => "readiness_timeout",
        ProtectedBundledRuntimeError::OwnershipMismatch => "ownership_mismatch",
        ProtectedBundledRuntimeError::InvalidState => "invalid_state",
        ProtectedBundledRuntimeError::RestartExhausted => "restart_exhausted",
        ProtectedBundledRuntimeError::ShutdownIncomplete => "shutdown_incomplete",
        ProtectedBundledRuntimeError::ProviderActivationNotReady(readiness) => match readiness {
            ProviderActivationReadinessV1::Ready => "provider_ready_invalid_state",
            ProviderActivationReadinessV1::CredentialMissing => "provider_credential_missing",
            ProviderActivationReadinessV1::CredentialAccessDenied => "provider_access_denied",
            ProviderActivationReadinessV1::CredentialIdentityMismatch => {
                "provider_identity_mismatch"
            }
            ProviderActivationReadinessV1::SecureStoreUnavailable => "provider_store_unavailable",
        },
        ProtectedBundledRuntimeError::LaunchAuthority(error) => match error {
            LaunchAuthorityError::MissingLaunchAuthority => "missing_launch_authority",
            LaunchAuthorityError::StaleLaunchAuthority => "stale_launch_authority",
            LaunchAuthorityError::ReusedLaunchAuthority => "reused_launch_authority",
            LaunchAuthorityError::MissingExpectedStableBinding => "stable_binding_missing",
            LaunchAuthorityError::UnexpectedExistingEventLog => "unexpected_event_log",
            LaunchAuthorityError::FirstActivationPreparationMismatch => "first_activation_mismatch",
            LaunchAuthorityError::FirstActivationCommitIncomplete => "first_activation_incomplete",
            LaunchAuthorityError::ExecutableIdentityMismatch => "executable_identity",
            LaunchAuthorityError::ProfileHashMismatch => "profile_hash_mismatch",
            LaunchAuthorityError::InstanceGenerationSessionMismatch => "session_binding_mismatch",
            LaunchAuthorityError::DowngradedExternalProfile => "external_profile_rejected",
            LaunchAuthorityError::UnsupportedPlatformBackend => "unsupported_platform",
            LaunchAuthorityError::ProtectedChannelUnavailable => "protected_channel",
            LaunchAuthorityError::ReadinessTimeout => "readiness_timeout",
            LaunchAuthorityError::ReadinessProofMismatch => "readiness_proof_mismatch",
            LaunchAuthorityError::RenewalReplay => "renewal_replay",
            LaunchAuthorityError::RenewalUnavailable => "renewal_unavailable",
            LaunchAuthorityError::OwnershipMismatch => "ownership_mismatch",
            LaunchAuthorityError::MissingProviderBinding => "provider_binding_missing",
            LaunchAuthorityError::ProviderModeMismatch => "provider_mode_mismatch",
            LaunchAuthorityError::ProviderProfileMismatch => "provider_profile_mismatch",
            LaunchAuthorityError::InvalidContract => "invalid_contract",
        },
    }
}

#[cfg(test)]
mod launch_diagnostic_tests {
    use super::*;

    #[test]
    fn failure_codes_are_fixed_and_do_not_format_error_payloads() {
        assert_eq!(
            protected_launch_failure_code(ProtectedBundledRuntimeError::LaunchAuthority(
                LaunchAuthorityError::ProviderProfileMismatch,
            )),
            "provider_profile_mismatch"
        );
        assert_eq!(
            protected_launch_failure_code(
                ProtectedBundledRuntimeError::ProviderActivationNotReady(
                    ProviderActivationReadinessV1::SecureStoreUnavailable,
                )
            ),
            "provider_store_unavailable"
        );
    }
}
