#![forbid(unsafe_code)]

//! gocode-opencode-compat — OpenCode baseline inventory profile.
//!
//! Phase 2a: read-only inventory registry + typed rejection.
//! Zero production dependencies. All operations -> Reject.

pub mod classify;
pub mod inventory;
pub mod profile;
pub mod translate;
