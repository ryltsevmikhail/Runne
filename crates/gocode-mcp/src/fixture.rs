mod debug;
mod mode;
mod model;
mod process;
mod process_gateway;
mod publication;
mod runtime;
mod schema;
mod transport;

#[cfg(test)]
mod process_gateway_tests;
#[cfg(test)]
mod runtime_activation_tests;
#[cfg(test)]
mod runtime_composition_tests;

pub use mode::{FixtureMcpFailure, FixtureMcpMode, FixtureProfile};
pub use model::{
    FixtureApprovalPolicy, FixtureCallResult, FixtureIdentity, FixtureInitialize, FixtureLimits,
    FixtureScript, FixtureStep, FixtureTool,
};
pub use process::{
    FixtureProcessComposition, FixtureProcessCompositionMetadata, McpProcessCall,
    derive_process_identity_binding,
};
pub use process_gateway::{McpProcessExecutor, McpProcessGatewayError, McpProcessToolGateway};
pub use runtime::{
    FixtureApproval, FixtureApprovalAuthority, FixtureAuditRecord, FixtureCallCapability,
    FixtureMcpRuntime, FixtureProcessApprovalAuthority, FixturePublication,
};
