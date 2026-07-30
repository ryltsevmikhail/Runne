use gocode_runtime_client::{ReplayClientErrorKind, ReplayRecoveryDisposition};

#[test]
fn replay_failures_map_to_closed_recovery_dispositions() {
    let cases = [
        (
            ReplayClientErrorKind::SessionExpired,
            ReplayRecoveryDisposition::Reconnectable,
        ),
        (
            ReplayClientErrorKind::Transport,
            ReplayRecoveryDisposition::Reconnectable,
        ),
        (
            ReplayClientErrorKind::Backpressure,
            ReplayRecoveryDisposition::Reconnectable,
        ),
        (
            ReplayClientErrorKind::BindingMismatch,
            ReplayRecoveryDisposition::Incompatible,
        ),
        (
            ReplayClientErrorKind::SchemaMismatch,
            ReplayRecoveryDisposition::Incompatible,
        ),
        (
            ReplayClientErrorKind::RetentionGap,
            ReplayRecoveryDisposition::ResyncRequired,
        ),
        (
            ReplayClientErrorKind::SensitivityDenied,
            ReplayRecoveryDisposition::Revoked,
        ),
        (
            ReplayClientErrorKind::AuthorizationRevoked,
            ReplayRecoveryDisposition::Revoked,
        ),
        (
            ReplayClientErrorKind::EventIdentityConflict,
            ReplayRecoveryDisposition::Fatal,
        ),
        (
            ReplayClientErrorKind::Integrity,
            ReplayRecoveryDisposition::Fatal,
        ),
        (
            ReplayClientErrorKind::LocalCallback,
            ReplayRecoveryDisposition::Fatal,
        ),
    ];

    for (kind, expected) in cases {
        assert_eq!(kind.recovery_disposition(), expected);
    }
}
