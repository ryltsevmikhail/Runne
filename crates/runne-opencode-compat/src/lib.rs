#![forbid(unsafe_code)]

//! runne-opencode-compat — OpenCode baseline inventory profile.
//!
//! Phase 2a: read-only inventory registry + typed rejection.
//! Phase 2b adds the fail-closed `session.create` compatibility boundary.

pub mod binding;
pub mod classify;
pub mod error;
pub mod inventory;
pub mod jsonc_import;
pub mod profile;
pub mod service;
pub mod translate;

pub use binding::*;
pub use error::*;
pub use service::*;
