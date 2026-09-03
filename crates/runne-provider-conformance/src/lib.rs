#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Provider-neutral, offline conformance helpers for adapter qualification.

mod errors;
mod fixtures;
mod identifiers;
mod request;
mod scripted;
mod stream;

pub use errors::{ProviderFailure, ProviderFailureKind, RetryMetadata, classify_provider_failure};
pub use fixtures::{ALL_FIXTURE_IDS, FixtureId, fixture};
pub use identifiers::{
    IdentifierError, IdentifierKind, NormalizedIdentifiers, normalize_identifier,
};
pub use request::{
    RedactionError, RequestContract, RequestContractError, WireRequest, assert_credential_free,
    assert_redacted_diagnostics,
};
pub use scripted::{
    CancellationDisposition, RequestObservation, ScriptedOutcome, ScriptedTransport,
};
pub use stream::{StreamContractError, StreamEvidence, validate_text_stream};
