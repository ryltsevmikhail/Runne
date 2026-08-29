//! Native-only credential enrollment host state. Step 5 owns daemon orchestration.

mod command;
mod host_prompt;
pub mod intent;
mod prepared;
mod projection;

pub use command::CredentialIntentIpc;
pub use intent::CredentialIntentRegistry;
pub use projection::CredentialIntentProjection;
