//! Native-only credential enrollment host state. Step 5 owns daemon orchestration.

mod command;
mod dispatch;
mod host_prompt;
pub mod intent;
mod prepared;
mod projection;
mod service_registration;

pub use command::CredentialIntentIpc;
pub use intent::CredentialIntentRegistry;
pub use prepared::ProtectedWriterReaperRegistry;
pub use prepared::{
    CredentialWriterReaperLastError, CredentialWriterReaperSnapshot, CredentialWriterReaperState,
};
pub use projection::CredentialIntentProjection;
pub use service_registration::{
    CredentialServiceRegistration, CredentialServiceRegistrationDisposition,
};

pub use dispatch::dispatch_credential_intent;
