#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MetadataQueryError {
    InvalidRequest,
    UnsupportedContract,
    SourceUnavailable,
    InvalidSnapshot,
    ScopeDenied,
    StaleGeneration,
    StaleSnapshot,
    OwnerClosed,
    NotFound,
    LimitExceeded,
    InternalUnavailable,
}
impl std::fmt::Display for MetadataQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedContract => "unsupported_contract",
            Self::SourceUnavailable => "source_unavailable",
            Self::InvalidSnapshot => "invalid_snapshot",
            Self::ScopeDenied => "scope_denied",
            Self::StaleGeneration => "stale_generation",
            Self::StaleSnapshot => "stale_snapshot",
            Self::OwnerClosed => "owner_closed",
            Self::NotFound => "not_found",
            Self::LimitExceeded => "limit_exceeded",
            Self::InternalUnavailable => "internal_unavailable",
        })
    }
}
impl std::fmt::Debug for MetadataQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for MetadataQueryError {}
