use gocode_runtime_client::{ReplayClientErrorKind, ReplayCursor, ReplayRecoveryDisposition};

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

#[test]
fn opaque_cursor_round_trips_only_through_explicit_native_storage_codec() {
    let bytes = b"gocode-replay-cursor-v1.7b7d";
    let cursor = ReplayCursor::from_storage_bytes(bytes).expect("valid opaque checkpoint");
    assert_eq!(cursor.storage_bytes(), bytes);
    let invalid = ReplayCursor::from_storage_bytes(b"gocode-replay-cursor-v1.00");
    let Err(error) = invalid else {
        panic!("invalid cursor body must fail closed");
    };
    assert_eq!(error.kind(), ReplayClientErrorKind::CursorInvalid);
}
