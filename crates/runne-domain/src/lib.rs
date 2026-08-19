#![forbid(unsafe_code)]
#![deny(missing_docs)]
// TODO: add doc comments to all public items, then remove this allow.
#![allow(missing_docs)]

//! runne-domain — core domain types, commands, events, aggregates.
//!
//! No async, no IO, no external dependencies.

pub mod agent_loop;
pub use agent_loop::{
    LoopDisposition, StepOutcomeRef, StepOutcomeType, WakeCondition, WakeEvidenceRef,
};
pub use context::ContextManifestRef;
pub use plan::PlanRevisionRef;
pub mod command;
pub mod context;
pub mod conversation;
pub mod error;
pub mod event;
pub mod id;
pub mod message;
pub mod plan;
pub mod project_workspace;
pub mod recovery;
pub mod reference;
pub mod replay;
pub mod security;
pub mod task_run;
pub mod timestamp;
pub mod verification;
