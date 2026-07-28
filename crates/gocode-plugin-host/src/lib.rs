#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Content-addressed plugin package authority contracts.

mod activation;
mod model;
mod package;
mod transport;

pub use activation::{
    ActivationState, PluginActivationReceipt, PluginActivationRequest, PluginActivationSnapshot,
    PluginLifecycleError, PluginTerminalEvidence,
};
pub use transport::{
    DurablePluginStartIntentAuthority, PluginBootstrapFrame, PluginGenerationPort,
    PluginGenerationPortError, PluginGenerationReadLease, PluginProcessLease, PluginProcessPort,
    PluginProcessPortError, PluginStartIntent, PluginStartIntentBinding, PluginStartIntentJournal,
    PluginStartIntentJournalError, PluginStartIntentJournalResult, PluginStartIntentPort,
    PluginStartIntentPortError, PluginStartReconciliation, PluginTransportPort,
    PluginTransportPortError,
};

pub use model::{
    InvalidPluginIdentifier, PluginActivationId, PluginClass, PluginDigest, PluginGeneration,
    PluginHookId, PluginHostProfileId, PluginTrust,
};
pub use package::{
    PluginAuthorityPort, PluginAuthorityPortError, PluginAuthorityRegistry, PluginHelloMetadata,
    PluginPackageAuthority, PluginPackageCapture, PluginPackageCaptureError, PluginPackageContent,
    PluginPackageSource, PluginPackageVerificationError, PluginPackageVerifier,
    VerifiedPluginPackage,
};
