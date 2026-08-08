#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Project-owned MCP contracts and bounded transport admission.
//!
//! ```compile_fail
//! use gocode_mcp::FixtureProcessApprovalAuthority;
//! ```
//! ```compile_fail
//! use gocode_mcp::FixtureProcessComposition;
//! ```
//! ```compile_fail
//! use gocode_mcp::FixtureProcessCompositionMetadata;
//! ```
//! ```compile_fail
//! use gocode_mcp::McpProcessCall;
//! ```
//! ```compile_fail
//! use gocode_mcp::McpProcessExecutor;
//! ```
//! ```compile_fail
//! use gocode_mcp::McpProcessGatewayError;
//! ```
//! ```compile_fail
//! use gocode_mcp::McpProcessToolGateway;
//! ```
//! ```compile_fail
//! use gocode_mcp::derive_process_identity_binding;
//! ```

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
    FixtureApproval, FixtureApprovalAuthority, FixtureApprovalPolicy, FixtureAuditProcessPhase,
    FixtureAuditProcessReason, FixtureAuditRecord, FixtureCallCapability, FixtureCallResult,
    FixtureIdentity, FixtureInitialize, FixtureLimits, FixtureMcpFailure, FixtureMcpMode,
    FixtureMcpRuntime, FixtureProfile, FixturePublication, FixtureScript, FixtureStep, FixtureTool,
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
