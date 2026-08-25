#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Provider-neutral contracts for Runne runtime adapters.
//!
//! Process-local credential capabilities deliberately fail durable trait bounds.
//!
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialGcClaim>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialGcClaim>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::CredentialGcClaim>();
//! ```
//!
//! Broker decoding remains internal to the provider crate.
//!
//! ```compile_fail
//! let _ = runne_provider::CredentialBrokerFrameCodec::decode(&[]);
//! ```

mod coordination;
mod credential;
mod digest;
mod fake;
mod id;
mod model;
mod port;
mod prepared;
mod pricing;
mod recovery;
mod stream;
mod text_profile;

pub use coordination::{
    PreparedProviderRecord, ProviderDispatchClaim, ProviderDispatchRepository,
    ProviderPreEffectRejection, ProviderRepositoryClaimOutcome, ProviderRepositoryError,
    ProviderRepositoryState,
};
pub use credential::{
    BeginCredentialOperation, BeginCredentialVerification, BindCredentialReadback,
    BrokerChannelBinding, CandidateSourceIdentity, ClaimCredentialOperation,
    ClosePreparedCredentialOperation, CompleteCredentialOperation, CompleteCredentialVerification,
    ContinuationBindingDigest, ContractBundleDigest, CredentialAuthorityPair,
    CredentialBindingDigest, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialClaimBinding, CredentialDispatchCapability, CredentialDisposition,
    CredentialEnrollmentError, CredentialFence, CredentialGcClaim, CredentialLease,
    CredentialLifecycleAuthority, CredentialLifecycleError, CredentialLifecycleRevision,
    CredentialLifecycleSnapshot, CredentialMeasurementSnapshot,
    CredentialNativeCreateAuthorization, CredentialNativeCreateClaim, CredentialNativeCreateIssuer,
    CredentialNativeCreateProgression, CredentialNativeCreateValidator, CredentialOperationAction,
    CredentialOperationId, CredentialOperationSnapshot, CredentialOperationState,
    CredentialProcessBinding, CredentialProvisionSource, CredentialRecoveryWork,
    CredentialReleaseMigrationBinding, CredentialTicketAttempt, CredentialTransitionEvidence,
    CredentialVerificationCapability, CredentialVerificationLease,
    CredentialVerificationObservation, CredentialVersionRef, CredentialVersionState,
    DaemonAuthorityId, DesktopExecutableIdentity, FailCredentialOperation, HardFenceProvider,
    IssueCredentialTicketDigest, NativeCredentialAuthority, NativeCredentialDeletionProof,
    ObserveNativeEffect, PrepareCredentialVersion, ProtectedSessionId,
    ProviderCredentialVersionStore, RawCredentialTicket, ReaderExecutableIdentity,
    ReconcileCredentialVersions, ReleaseManifestDigest, RevokeCredentialVersion,
    TombstoneCredentialOperation, TransitionCommand, WriterExecutableIdentity,
    WriterIdentityMigrationPhase, WriterLaunchId, WriterProcessHandleIdentity,
    WriterProcessStartIdentity, allows_structural_transition,
};
pub use digest::{
    CanonicalProviderError, ProviderCallDigest, ProviderCallDigestVersion,
    canonical_provider_call_digest, canonical_provider_call_digest_for_version,
    provider_call_wire_bytes_for_version,
};
pub use fake::{ScriptedProvider, ScriptedProviderError};
pub use id::{DispatchAttemptId, InvalidProviderId, ProviderCallId, ProviderId, ProviderStreamId};
pub use model::{
    MAX_PROVIDER_TEXT_INPUT_BYTES, MAX_PROVIDER_TEXT_INPUT_TOTAL_BYTES, MAX_PROVIDER_TEXT_INPUTS,
    ModelRef, ProviderCall, ProviderCallError, ProviderCapability, ProviderFinishReason,
    ProviderInputRole, ProviderTextInput,
};
pub use port::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, DispatchRequestError,
    PrepareError, ProviderFuture, ProviderPort, ReconcileRequest, ReconciliationDisposition,
};
pub use prepared::{PreparedRequest, PreparedRequestRef};
pub use pricing::{ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError};
pub use recovery::{
    CredentialMatcher, NativeSecretRef, ScanStep, ScannerCheckpoint, ScannerError,
    ScannerTerminalDisposition, ScannerUncertainReason, SecureStoreError, TailBinding,
    WithheldTailStore, scan_provider_chunk,
};
pub use stream::{
    MAX_PROVIDER_TEXT_DELTA_BYTES, MAX_PROVIDER_TOOL_ARGUMENT_BYTES,
    MAX_PROVIDER_TOOL_IDENTIFIER_BYTES, MAX_PROVIDER_USAGE_TOKENS, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamItem, ProviderStreamValidator,
    ProviderTerminalDisposition, ProviderUsage, ProviderUsageError, StreamCursor, StreamError,
};
pub use text_profile::TextProviderProfile;
