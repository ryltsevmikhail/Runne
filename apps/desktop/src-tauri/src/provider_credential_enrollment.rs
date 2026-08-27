//! Native-only credential enrollment host state. Step 5 owns daemon orchestration.

mod command;
mod projection;

pub use command::CredentialIntentIpc;
pub use projection::CredentialIntentProjection;
