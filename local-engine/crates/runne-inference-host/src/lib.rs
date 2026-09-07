//! runne-inference-host: private supervised inference host. Inherited
//! private IPC only; launch secret and artifact handle arrive through
//! protected channels; `env_clear` at entry; no shell; stdout/stderr are
//! non-authoritative diagnostics.

pub mod artifact_transport;
pub mod backend;
pub mod error;
pub mod fake_backend;
pub mod generate;
pub mod load;
pub mod session;
pub mod shutdown;
pub mod worker_backend;

pub use backend::{BackendConfig, BackendPort, GenerationCtx, LoadRequest, LoadedModel};
pub use error::HostError;
#[cfg(feature = "backend-fake")]
pub use fake_backend::FakeBackend;
pub use session::{HostSession, HostState};
pub use worker_backend::{WorkerBackend, WorkerBinding};
