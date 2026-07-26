#![forbid(unsafe_code)]
//! gocode-domain — pure domain types, IDs, events, commands, state machines.
//! No async, no IO, no external dependencies.

pub mod command;
pub mod error;
pub mod event;
pub mod task_run;
pub mod id;
pub mod timestamp;
