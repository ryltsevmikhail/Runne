//! runne-llama-worker: the only first-party package allowed to depend
//! on llama.cpp. Speaks the worker protocol (`WORKER_PURPOSE` HKDF
//! domain); engine selection is a compile-time feature so the default
//! build stays free of native code.

pub mod engine;
pub mod grammar;
pub mod json_validate;
pub mod reasoning;
pub mod session;
mod session_runner;
mod session_usage;

#[cfg(feature = "backend-llama-cpp")]
pub mod llama_context;
#[cfg(feature = "backend-llama-cpp")]
pub mod llama_model;
#[cfg(feature = "backend-llama-cpp")]
pub mod usage;

pub use engine::{EngineBackend, EngineItem, EngineOutcome};
pub use session::WorkerIdentity;
pub use session_runner::serve;
