#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Field-level docs deferred to later phases; all module/type-level docs present.
#![allow(missing_docs)]
//! gocode-domain — pure domain types, IDs, events, commands, state machines.
//! No async, no IO, no external dependencies.

pub mod command;
pub mod conversation;
pub mod error;
pub mod event;
pub mod id;
pub mod security;
pub mod task_run;
pub mod timestamp;
