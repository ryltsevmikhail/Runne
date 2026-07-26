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
pub mod types;

mod supervisor;
mod worker;

mod startup;
pub use startup::{
    BorrowedLease, Runtime, RuntimeGenerationId, RuntimeStartError, TokioRuntimeContext,
};
pub mod bundle;
