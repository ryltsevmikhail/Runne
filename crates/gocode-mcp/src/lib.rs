#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Project-owned MCP contracts and bounded transport admission.

mod discovery;
mod fixture;
mod model;
mod profile;
mod transport;

pub use discovery::{
    McpDiscoveryError, McpDiscoverySnapshot, McpDispatchBinding, McpDispatchCapabilityError,
    McpGenerationAdvanceError, McpGenerationAuthority, McpGenerationClaimError, McpServerKind,
    McpToolDescriptor, McpToolDispatchCapability, McpToolExecutionClass, McpToolGateway,
    McpToolGatewayError, PublishedMcpTools, publish_mcp_tools,
};
pub use fixture::{
    FixtureApproval, FixtureApprovalAuthority, FixtureApprovalPolicy, FixtureAuditRecord,
    FixtureCallCapability, FixtureCallResult, FixtureIdentity, FixtureInitialize, FixtureLimits,
    FixtureMcpFailure, FixtureMcpMode, FixtureMcpRuntime, FixtureProcessApprovalAuthority,
    FixtureProcessComposition, FixtureProcessCompositionMetadata, FixtureProfile,
    FixturePublication, FixtureScript, FixtureStep, FixtureTool, McpProcessCall,
    McpProcessExecutor, McpProcessGatewayError, McpProcessToolGateway,
    derive_process_identity_binding,
};
pub use model::{
    InvalidMcpIdentity, McpConnectionId, McpInvocationId, McpNormalizedMessage, McpRequestId,
    McpRuntimeInstanceId, McpServerId, McpSessionId,
};
pub use profile::{
    McpSdkIntegrationEvidence, McpSdkIntegrationProfileId, McpSdkIntegrationProfileRef,
    PRODUCTION_MCP_SDK_ENABLED, SdkProfileUnavailable,
};
pub use transport::{
    BoundedMcpTransport, McpClientPort, McpProtocolCompletionPort, McpTransportError,
    McpTransportLimits, McpTransportPort,
};
