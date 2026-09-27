use runne_provider_deepseek::DeepSeekStreamError;

/// Coarse, non-secret class for the provider's observed HTTP response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeepSeekHttpStatusClass {
    Ok200,
    BadRequest400,
    Unauthorized401,
    PaymentRequired402,
    Forbidden403,
    NotFound404,
    TooManyRequests429,
    Other2xx,
    Redirect3xx,
    Other4xx,
    Server5xx,
    Other,
}

impl DeepSeekHttpStatusClass {
    pub(crate) fn from_status(status: u16) -> Self {
        match status {
            200 => Self::Ok200,
            400 => Self::BadRequest400,
            401 => Self::Unauthorized401,
            402 => Self::PaymentRequired402,
            403 => Self::Forbidden403,
            404 => Self::NotFound404,
            429 => Self::TooManyRequests429,
            _ if status / 100 == 2 => Self::Other2xx,
            _ if status / 100 == 3 => Self::Redirect3xx,
            _ if status / 100 == 4 => Self::Other4xx,
            _ if status / 100 == 5 => Self::Server5xx,
            _ => Self::Other,
        }
    }
}

/// Fixed stages at the authorized DeepSeek dispatch boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeepSeekEffectDiagnostic {
    ReceiptRejected,
    RequestIdRejected,
    MaterializationStarted,
    Materialized,
    MaterializationMissing,
    MaterializationAccessDenied,
    AuthorizationHeaderRejected,
    RequestSendStarted,
    RequestSendFailed,
    ResponseStatus(DeepSeekHttpStatusClass),
    ResponseContractSse,
    ResponseContractJsonRejection,
    ResponseContractRejected,
    BodyIdleTimeout,
    BodyReadFailed,
    BodyChunkLimitExceeded,
    BodyByteLimitExceeded,
    BodyEmpty,
    BodyComplete,
    ResponseConstructionFailed,
    DecodeFailed(DeepSeekStreamError),
    #[cfg(feature = "linux-native-enrollment-qualification")]
    DecodeDetail {
        error: DeepSeekStreamError,
        detail: runne_provider_deepseek::DeepSeekDecodeDiagnostic,
    },
    Decoded,
    StreamStoreFailed,
    StreamStored,
    DeadlineExpired,
}

/// Optional qualification observer. Implementations receive only fixed codes.
pub trait DeepSeekEffectObserver: Send + Sync {
    fn observe(&self, diagnostic: DeepSeekEffectDiagnostic);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_exposes_only_closed_classes() {
        assert_eq!(
            DeepSeekHttpStatusClass::from_status(401),
            DeepSeekHttpStatusClass::Unauthorized401
        );
        assert_eq!(
            DeepSeekHttpStatusClass::from_status(429),
            DeepSeekHttpStatusClass::TooManyRequests429
        );
        assert_eq!(
            DeepSeekHttpStatusClass::from_status(503),
            DeepSeekHttpStatusClass::Server5xx
        );
        assert_eq!(
            DeepSeekHttpStatusClass::from_status(799),
            DeepSeekHttpStatusClass::Other
        );
    }
}
