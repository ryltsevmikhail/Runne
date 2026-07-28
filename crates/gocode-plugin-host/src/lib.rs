#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Content-addressed plugin package authority contracts.

mod activation;
mod hooks;
mod model;
mod package;
mod tools;
mod transport;

pub use activation::{
    ActivationState, PluginActivationReceipt, PluginActivationRequest, PluginActivationSnapshot,
    PluginLifecycleError, PluginTerminalEvidence,
};
pub use hooks::{
    MAX_PLUGIN_HOOK_DEFINITIONS, MAX_PLUGIN_HOOK_PAYLOAD_BYTES, PluginHookClockPort,
    PluginHookDefinition, PluginHookDescriptorAuthorityPort, PluginHookDispatch,
    PluginHookDispatchAuthorityPort, PluginHookDispatchClaim, PluginHookDispatchClaimResult,
    PluginHookDispatchError, PluginHookDispatchJournal, PluginHookDispatchJournalError,
    PluginHookDispatchJournalKey, PluginHookDispatchJournalResult, PluginHookDisposition,
    PluginHookFailurePolicy, PluginHookInvocation, PluginHookInvocationError,
    PluginHookRecoveredDispatch, PluginHookResult, VerifiedPluginHookDescriptors, dispatch_hooks,
    ordered_plugin_hooks, verify_plugin_hook_descriptors,
};
pub use transport::{
    DurablePluginStartIntentAuthority, PluginActiveFence, PluginBootstrapFrame,
    PluginCleanupEvidence, PluginDrainEvidence, PluginGenerationPort, PluginGenerationPortError,
    PluginGenerationReadLease, PluginProcessLease, PluginProcessPort, PluginProcessPortError,
    PluginStartIntent, PluginStartIntentBinding, PluginStartIntentJournal,
    PluginStartIntentJournalError, PluginStartIntentJournalResult, PluginStartIntentOrigin,
    PluginStartIntentPort, PluginStartIntentPortError, PluginStartReconciliation,
    PluginTransportPort, PluginTransportPortError,
};

pub use model::{
    InvalidPluginIdentifier, PluginActivationId, PluginClass, PluginDigest, PluginGeneration,
    PluginHookId, PluginHookInvocationId, PluginHostProfileId, PluginTrust,
};
pub use package::{
    MAX_MANIFEST_BYTES, MAX_PACKAGE_FILE_BYTES, MAX_PACKAGE_FILES, MAX_PACKAGE_PATH_BYTES,
    MAX_PACKAGE_PATH_DEPTH, MAX_PACKAGE_RETAINED_BYTES, MAX_PROFILE_OR_TRUST_BYTES,
    PluginAuthorityPort, PluginAuthorityPortError, PluginAuthorityRegistry, PluginHelloMetadata,
    PluginPackageAuthority, PluginPackageCapture, PluginPackageCaptureError, PluginPackageContent,
    PluginPackageFile, PluginPackageFileKind, PluginPackageSource, PluginPackageVerificationError,
    PluginPackageVerifier, VerifiedPluginPackage,
};
pub use tools::{
    ActivePluginToolset, MAX_PLUGIN_TOOL_DEFINITIONS, PluginToolDescriptor,
    PluginToolDescriptorAuthorityPort, PluginToolDispatchError, PluginToolPublicationError,
    VerifiedPluginToolDescriptors, activate_plugin_tools, publish_plugin_tools,
    verify_plugin_tool_descriptors,
};
