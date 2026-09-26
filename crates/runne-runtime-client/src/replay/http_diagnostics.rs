use super::{ReplayClientError, ReplayClientErrorKind};

pub(super) fn report_replay_error(status: u16, error: &ReplayClientError) {
    crate::canonical::report_http_diagnostic(
        "replay",
        "response",
        Some(status),
        replay_error_kind(error.kind()),
    );
}

const fn replay_error_kind(kind: ReplayClientErrorKind) -> &'static str {
    match kind {
        ReplayClientErrorKind::InvalidRequest => "invalid_request",
        ReplayClientErrorKind::Transport => "transport",
        ReplayClientErrorKind::StreamSilence => "stream_silence",
        ReplayClientErrorKind::Backpressure => "backpressure",
        ReplayClientErrorKind::SessionExpired => "session_expired",
        ReplayClientErrorKind::PeerIdentityMismatch => "peer_identity_mismatch",
        ReplayClientErrorKind::BindingMismatch => "binding_mismatch",
        ReplayClientErrorKind::SchemaMismatch => "schema_mismatch",
        ReplayClientErrorKind::RetentionGap => "retention_gap",
        ReplayClientErrorKind::SensitivityDenied => "sensitivity_denied",
        ReplayClientErrorKind::AuthorizationRevoked => "authorization_revoked",
        ReplayClientErrorKind::CursorInvalid => "cursor_invalid",
        ReplayClientErrorKind::AggregateMismatch => "aggregate_mismatch",
        ReplayClientErrorKind::NonMonotonicSequence => "non_monotonic_sequence",
        ReplayClientErrorKind::EventIdentityConflict => "event_identity_conflict",
        ReplayClientErrorKind::Integrity => "integrity",
        ReplayClientErrorKind::LocalCallback => "local_callback",
        ReplayClientErrorKind::ResponseTooLarge => "response_too_large",
        ReplayClientErrorKind::UnexpectedContentType => "unexpected_content_type",
        ReplayClientErrorKind::InvalidResponse => "invalid_response",
    }
}

#[cfg(test)]
mod tests {
    use super::replay_error_kind;
    use crate::replay::ReplayClientErrorKind;

    #[test]
    fn replay_diagnostics_use_only_stable_error_kinds() {
        assert_eq!(
            replay_error_kind(ReplayClientErrorKind::AuthorizationRevoked),
            "authorization_revoked"
        );
        assert_eq!(
            replay_error_kind(ReplayClientErrorKind::SessionExpired),
            "session_expired"
        );
    }
}
