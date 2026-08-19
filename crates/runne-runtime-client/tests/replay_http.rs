use runne_runtime_client::{ReplayClientErrorKind, ReplayRecoveryDisposition};

#[path = "replay_http_support/mod.rs"]
mod replay_http_support;

use replay_http_support::*;

include!("replay_http_retention_parts/valid.rs");
include!("replay_http_retention_parts/adversarial.rs");

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
            ReplayRecoveryDisposition::Fatal,
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

#[test]
fn information_free_sse_retention_terminal_cannot_authorize_resync() {
    use runne_runtime_client::ReplayTerminalCode;

    assert_eq!(
        ReplayTerminalCode::RetentionGap.recovery_disposition(),
        ReplayRecoveryDisposition::Fatal,
    );
}
