#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![deny(missing_docs)]
#![allow(missing_docs)]

//! `gocode-runtime` — multi-worker dispatch runtime for GOCODE.

pub mod config;
pub mod controller;
pub mod error;
pub mod gate;
pub mod handle;
pub mod mcp;
pub mod migration_drain;
pub mod migration_fence;
pub mod migration_router;
pub mod migration_shadow;
pub mod plugin_host;
pub mod provider_tool;
pub mod session_host;
pub mod types;

mod supervisor;
mod worker;

mod startup;
pub use startup::{
    BorrowedLease, Runtime, RuntimeGenerationId, RuntimeStartError, TokioRuntimeContext,
};
pub mod bundle;

pub use mcp::{McpActivationError, McpActivationRequest, McpRuntimeActivation};
pub use plugin_host::{
    ExtensionRootBinding, ExtensionRootExit, ExtensionRootKind, ExtensionRootPort,
    ExtensionRootReceipt, ExtensionRootState, ExtensionSupervisorError, RuntimeExtensionSupervisor,
    RuntimeRootLease,
};
