use std::sync::Arc;

use runne_daemon_deepseek_effect::{
    DeepSeekEffectDiagnostic as Diagnostic, DeepSeekEffectObserver,
    DeepSeekHttpStatusClass as Status,
};
use runne_secure_store::ProviderCredentialDispatchMaterializer;

struct DeepSeekQualificationObserver;

impl DeepSeekEffectObserver for DeepSeekQualificationObserver {
    fn observe(&self, diagnostic: Diagnostic) {
        let (stage, succeeded) = stage_for(diagnostic);
        crate::protected_activation::linux_pair_diagnostics::record(stage, succeeded);
    }
}

pub(super) fn production_effect(
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
) -> Result<
    Arc<dyn runne_daemon_deepseek_effect::DeepSeekEffect>,
    runne_daemon_deepseek_effect::DeepSeekEffectError,
> {
    <dyn runne_daemon_deepseek_effect::DeepSeekEffect>::production_with_observer(
        materializer,
        Arc::new(DeepSeekQualificationObserver),
    )
}

fn stage_for(diagnostic: Diagnostic) -> (&'static str, bool) {
    use Diagnostic as D;
    let stage = match diagnostic {
        D::ReceiptRejected => "deepseek_receipt_rejected",
        D::RequestIdRejected => "deepseek_request_id_rejected",
        D::MaterializationStarted => "deepseek_materialization_started",
        D::Materialized => "deepseek_materialized",
        D::MaterializationMissing => "deepseek_materialization_missing",
        D::MaterializationAccessDenied => "deepseek_materialization_denied",
        D::AuthorizationHeaderRejected => "deepseek_authorization_header_rejected",
        D::RequestSendStarted => "deepseek_request_send_started",
        D::RequestSendFailed => "deepseek_request_send_failed",
        D::ResponseStatus(status) => status_stage(status),
        D::ResponseContractSse => "deepseek_contract_sse",
        D::ResponseContractJsonRejection => "deepseek_contract_json_rejection",
        D::ResponseContractRejected => "deepseek_contract_rejected",
        D::BodyIdleTimeout => "deepseek_body_idle_timeout",
        D::BodyReadFailed => "deepseek_body_read_failed",
        D::BodyChunkLimitExceeded => "deepseek_body_chunk_limit",
        D::BodyByteLimitExceeded => "deepseek_body_byte_limit",
        D::BodyEmpty => "deepseek_body_empty",
        D::BodyComplete => "deepseek_body_complete",
        D::ResponseConstructionFailed => "deepseek_response_construction_failed",
        D::DecodeFailed(error) => return (decode_stage(error), false),
        D::DecodeDetail { error, detail } => {
            #[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
            runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_deepseek_decode_detail(
                detail.ordinals(),
            );
            return (decode_stage(error), false);
        }
        D::Decoded => "deepseek_decode_ok",
        D::StreamStoreFailed => "deepseek_stream_store_failed",
        D::StreamStored => "deepseek_stream_stored",
        D::DeadlineExpired => "deepseek_deadline_expired",
    };
    let succeeded = !matches!(
        diagnostic,
        D::ReceiptRejected
            | D::RequestIdRejected
            | D::MaterializationMissing
            | D::MaterializationAccessDenied
            | D::AuthorizationHeaderRejected
            | D::RequestSendFailed
            | D::ResponseContractRejected
            | D::BodyIdleTimeout
            | D::BodyReadFailed
            | D::BodyChunkLimitExceeded
            | D::BodyByteLimitExceeded
            | D::BodyEmpty
            | D::ResponseConstructionFailed
            | D::StreamStoreFailed
            | D::DeadlineExpired
    );
    (stage, succeeded)
}

fn status_stage(status: Status) -> &'static str {
    match status {
        Status::Ok200 => "deepseek_http_status_200",
        Status::BadRequest400 => "deepseek_http_status_400",
        Status::Unauthorized401 => "deepseek_http_status_401",
        Status::PaymentRequired402 => "deepseek_http_status_402",
        Status::Forbidden403 => "deepseek_http_status_403",
        Status::NotFound404 => "deepseek_http_status_404",
        Status::TooManyRequests429 => "deepseek_http_status_429",
        Status::Other2xx => "deepseek_http_status_2xx",
        Status::Redirect3xx => "deepseek_http_status_3xx",
        Status::Other4xx => "deepseek_http_status_4xx",
        Status::Server5xx => "deepseek_http_status_5xx",
        Status::Other => "deepseek_http_status_other",
    }
}

fn decode_stage(error: runne_provider_deepseek::DeepSeekStreamError) -> &'static str {
    use runne_provider_deepseek::DeepSeekStreamError as E;
    match error {
        E::MalformedEvent => "deepseek_decode_malformed",
        E::UnknownEvent => "deepseek_decode_unknown_event",
        E::CorrelationMismatch => "deepseek_decode_correlation",
        E::IllegalTransition => "deepseek_decode_transition",
        E::StreamLimitExceeded => "deepseek_decode_limit",
        E::TerminalMissing => "deepseek_decode_terminal_missing",
        E::InvalidUsage => "deepseek_decode_usage_invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider_deepseek::DeepSeekStreamError;

    #[test]
    fn diagnostic_mapping_is_closed_and_status_specific() {
        assert_eq!(
            stage_for(Diagnostic::ResponseStatus(Status::Unauthorized401)),
            ("deepseek_http_status_401", true)
        );
        assert_eq!(
            stage_for(Diagnostic::DecodeFailed(
                DeepSeekStreamError::MalformedEvent
            )),
            ("deepseek_decode_malformed", false)
        );
        assert_eq!(
            stage_for(Diagnostic::MaterializationAccessDenied),
            ("deepseek_materialization_denied", false)
        );
    }
}
