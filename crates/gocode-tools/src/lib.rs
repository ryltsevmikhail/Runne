#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Runtime-neutral tool registry and execution gateway contracts.

mod executor;
mod gateway;
mod model;
mod output;
mod process;
mod registry;

pub use executor::{
    CompletionMode, EffectAdmission, NoTerminalCompletion, ProcessCompletion,
    ProcessToolExecutorPort, ProtocolCompletion, ProtocolToolExecutorPort, ToolExecutionHandle,
    ToolExecutorError, ToolExecutorPort,
};
pub use gateway::{
    GateStage, ToolAdmissionDecision, ToolAdmissionError, ToolAdmissionPort, ToolCancelDisposition,
    ToolCancelRequest, ToolCloseEvidence, ToolCloseRequest, ToolDispatchRequest, ToolGateway,
    ToolGatewayError, ToolProtocolCloseRequest, ToolTerminalDisposition,
};
pub use model::{
    InvalidToolDefinition, InvalidToolIdentity, SandboxProfile, ToolClass, ToolDefinition,
    ToolDispatchBinding, ToolId, ToolRef, ToolVersion, ToolsetSnapshot,
};
pub use output::{BlobRef, InvalidOutputContract, RawToolOutput, ToolOutput, ToolOutputBounds};
pub use process::{
    ProcessCloseMaterial, ProcessLifecycleReport, ProcessOperation, ProcessStartRequest,
    ProcessToolError, ProcessToolExecutor,
};
pub use registry::{RegisterToolOutcome, ToolRegistry, ToolRegistryError};
