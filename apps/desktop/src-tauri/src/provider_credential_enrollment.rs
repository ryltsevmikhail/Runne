//! Native-only credential enrollment host state. Step 5 owns daemon orchestration.

mod command;
pub mod intent;
mod projection;

pub use command::CredentialIntentIpc;
pub use intent::CredentialIntentRegistry;
pub use projection::CredentialIntentProjection;
