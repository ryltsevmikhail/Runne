use crate::canonical::{RuntimeApiError, RuntimeApiErrorKind};

pub(super) fn page_limit(limit: u16) -> Result<(), RuntimeApiError> {
    (limit != 0 && limit <= 100)
        .then_some(())
        .ok_or_else(invalid_request)
}

pub(super) fn invalid_request() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest)
}

pub(super) fn invalid_response() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)
}

pub(super) fn map_transport(_: reqwest::Error) -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)
}
