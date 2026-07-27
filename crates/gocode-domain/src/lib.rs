#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]

//! gocode-domain — core domain types, commands, events, aggregates.
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
<<<<<<< HEAD
pub mod security;
=======
pub mod plan;
pub mod recovery;
pub mod reference;
>>>>>>> dcc4d82 (feat(agent-loop): implement phase 5 core contracts)
pub mod task_run;
pub mod timestamp;
pub mod verification;
