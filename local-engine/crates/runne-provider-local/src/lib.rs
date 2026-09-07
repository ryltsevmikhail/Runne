//! runne-provider-local: the local provider adapter surface — artifact
//! broker port, one-time load grants and ancillary-fd frame binding.

pub mod adapter;
mod adapter_context;
pub mod artifact_broker;
pub mod artifact_transport;
pub mod cancellation;
pub mod dispatch;
pub mod error;
pub mod grant;
pub mod permit;
pub use prepared::PreparedRequest;
pub mod context_admission;
pub mod port;
pub mod prepared;
pub mod queue;
pub mod reasoning_fold;
pub mod reconcile;
pub mod recovery;
pub mod resource_enforcement;
pub mod resource_manager;
pub mod resource_quote;
pub mod sampling;
pub mod sampling_error;
pub mod selected_model;
pub mod settlement;
pub mod streams;
pub mod structured;
pub mod structured_schema;
pub mod tool_parser;
pub mod tool_protocol;

pub use adapter::LocalProviderAdapter;
pub use artifact_broker::ModelArtifactBrokerPort;
pub use error::ProviderError;
pub use grant::{ArtifactGrant, ArtifactGrantRequest, GrantRole};
pub use port::{
    CancelDisposition, DispatchRequest, ProviderCall, ProviderPort, ProviderStream, Reconciliation,
    StreamItem,
};
pub use recovery::{CleanupEvidence, RecoveryLedger};
pub use sampling::{BackendBounds, EffectiveSampling, ProfileDefaults, SAMPLING_NAMESPACE};
pub use sampling_error::SamplingError;
pub use structured::{STRUCTURED_NAMESPACE, StructuredError, StructuredMode, StructuredRequest};
pub use structured_schema::SchemaError as SchemaSubsetError;
