mod descriptor;
mod issuance;

pub use descriptor::{
    McpDispatchCapabilityError, McpToolDescriptor, McpToolDispatchCapability, McpToolExecutionClass,
};
pub(crate) use issuance::ProcessCallBindingError;
#[cfg(test)]
pub(crate) use issuance::derive_process_lifecycle_binding;

include!("discovery/catalog.rs");
include!("discovery/generation.rs");
include!("discovery/gateway.rs");

#[cfg(test)]
mod generation_tests;
