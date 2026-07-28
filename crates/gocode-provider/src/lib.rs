#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Provider-neutral contracts for GOCODE runtime adapters.

mod coordination;
mod digest;
mod fake;
mod id;
mod model;
mod port;
mod stream;

pub use coordination::{
    PreparedProviderRecord, ProviderDispatchClaim, ProviderDispatchRepository,
    ProviderRepositoryClaimOutcome, ProviderRepositoryError, ProviderRepositoryState,
};
pub use digest::{CanonicalProviderError, ProviderCallDigest, canonical_provider_call_digest};
pub use fake::{ScriptedProvider, ScriptedProviderError};
pub use id::{DispatchAttemptId, InvalidProviderId, ProviderCallId, ProviderId, ProviderStreamId};
pub use model::{
    ModelRef, ProviderCall, ProviderCallError, ProviderCapability, ProviderFinishReason,
};
pub use port::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, PreparedRequestRef, ProviderFuture, ProviderPort, ReconcileRequest,
    ReconciliationDisposition,
};
pub use stream::{
    ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamItem, StreamCursor, StreamError,
};
