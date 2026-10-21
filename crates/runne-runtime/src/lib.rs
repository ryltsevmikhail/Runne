#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![deny(missing_docs)]
#![allow(missing_docs)]

//! `runne-runtime` — multi-worker dispatch runtime for Runne.

pub mod approval_host;
pub mod command_reconciliation_host;
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
pub mod opencode_session;
pub mod plugin_host;
pub mod process_host;
pub mod project_workspace_host;
pub mod provider_execution;
pub mod provider_redaction;
pub mod provider_tool;
pub mod qualification_matrix;
pub mod session_host;
pub mod task_run_host;
pub mod taskrun_auto_worker;
pub mod types;
pub mod workspace_diff_host;
pub mod workspace_editor_host;
pub mod workspace_file_host;

mod extension_query;
mod supervisor;
mod worker;

mod startup;
pub use approval_host::RuntimeApprovalHost;
pub use process_host::RuntimeProcessHost;
pub use project_workspace_host::{PROJECT_WORKSPACE_WORKER_CAPACITY, RuntimeProjectWorkspaceHost};
pub use startup::{
    BorrowedLease, Runtime, RuntimeGenerationId, RuntimeStartError, TokioRuntimeContext,
};
pub use task_run_host::RuntimeTaskRunHost;
pub use task_run_host::TaskRunEffectsEnricher;
pub use taskrun_auto_worker::{AutomaticTaskRunError, AutomaticTaskRunService};
pub use workspace_diff_host::RuntimeWorkspaceDiffHost;
pub use workspace_editor_host::RuntimeWorkspaceEditorHost;
pub use workspace_file_host::RuntimeWorkspaceFileHost;
pub mod bundle;
pub mod canonical_conversation_host;
pub mod canonical_provider_execution;
pub mod contract_generation;

pub use canonical_conversation_host::{
    DeterministicTextProvider, LocalTextProvider, LocalTextProviderError,
    RuntimeCanonicalConversationHost,
};
pub use canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
    CanonicalProviderExecutionService,
};
pub use command_reconciliation_host::{
    COMMAND_RECONCILIATION_WORKER_CAPACITY, RuntimeCommandReconciliationHost,
};
pub use mcp::{McpActivationError, McpActivationRequest, McpRuntimeActivation};
pub use plugin_host::{
    ExtensionRootBinding, ExtensionRootExit, ExtensionRootKind, ExtensionRootPort,
    ExtensionRootReceipt, ExtensionRootState, ExtensionSupervisorError, RuntimeExtensionSupervisor,
    RuntimeRootLease,
};
