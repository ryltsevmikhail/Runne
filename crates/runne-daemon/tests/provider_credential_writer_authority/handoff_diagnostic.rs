use runne_platform_desktop::ProtectedBundledRuntimeError as Error;

/// Closed failure category for one writer-handoff error, for failure output
/// only. The mapping is intentionally non-exhaustive: new closed variants
/// land in the shared bucket until a scenario needs to distinguish them.
pub(super) fn writer_handoff_category(error: &Error) -> &'static str {
    match error {
        Error::OwnershipMismatch => "ownership",
        Error::InvalidState => "state",
        Error::ProtectedChannelUnavailable => "channel",
        Error::ReadinessTimeout => "readiness",
        Error::SpawnFailed => "spawn",
        Error::ExecutableIdentityMismatch => "identity",
        _ => "other-closed-category",
    }
}

/// Prints the closed failure category for one writer-handoff error.
pub(super) fn report_handoff_failure(error: &Error) {
    eprintln!("writer-handoff-category={}", writer_handoff_category(error));
}
