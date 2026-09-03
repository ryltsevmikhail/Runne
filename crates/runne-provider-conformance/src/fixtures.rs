/// Governed offline fixture identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureId {
    /// Successful text-only response.
    SuccessTextOnly,
    /// Fragmented normalized stream.
    StreamFragments,
    /// Authentication rejection.
    AuthenticationFailure,
    /// Rate limit with retry metadata.
    RateLimit,
    /// Malformed response.
    MalformedResponse,
    /// Bounded timeout marker.
    Timeout,
    /// Cancellation marker.
    Cancellation,
    /// Unknown model rejection.
    UnknownModel,
}

/// Every fixture shipped by the kit.
pub const ALL_FIXTURE_IDS: [FixtureId; 8] = [
    FixtureId::SuccessTextOnly,
    FixtureId::StreamFragments,
    FixtureId::AuthenticationFailure,
    FixtureId::RateLimit,
    FixtureId::MalformedResponse,
    FixtureId::Timeout,
    FixtureId::Cancellation,
    FixtureId::UnknownModel,
];

/// Returns one immutable sanitized fixture body.
#[must_use]
pub const fn fixture(id: FixtureId) -> &'static [u8] {
    match id {
        FixtureId::SuccessTextOnly => include_bytes!("../fixtures/success_text_only.json"),
        FixtureId::StreamFragments => include_bytes!("../fixtures/stream_fragments.json"),
        FixtureId::AuthenticationFailure => include_bytes!("../fixtures/auth_failure.json"),
        FixtureId::RateLimit => include_bytes!("../fixtures/rate_limit.json"),
        FixtureId::MalformedResponse => include_bytes!("../fixtures/malformed_response.json"),
        FixtureId::Timeout => include_bytes!("../fixtures/timeout.json"),
        FixtureId::Cancellation => include_bytes!("../fixtures/cancellation.json"),
        FixtureId::UnknownModel => include_bytes!("../fixtures/unknown_model.json"),
    }
}
