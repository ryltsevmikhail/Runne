mod debug;
mod mode;
mod model;
mod process;
mod process_call;
mod process_gateway;
mod publication;
mod runtime;
mod schema;
mod transport;

#[cfg(test)]
mod process_call_tests;
#[cfg(test)]
mod process_gateway_tests;
#[cfg(test)]
mod runtime_activation_tests;
#[cfg(test)]
mod runtime_composition_tests;
#[cfg(test)]
mod runtime_process_tests;

pub use mode::{FixtureMcpFailure, FixtureMcpMode, FixtureProfile};
pub use model::{
    FixtureApprovalPolicy, FixtureCallResult, FixtureIdentity, FixtureInitialize, FixtureLimits,
    FixtureScript, FixtureStep, FixtureTool,
};
pub use runtime::{
    FixtureApproval, FixtureApprovalAuthority, FixtureAuditProcessPhase, FixtureAuditProcessReason,
    FixtureAuditRecord, FixtureCallCapability, FixtureMcpRuntime, FixturePublication,
};
