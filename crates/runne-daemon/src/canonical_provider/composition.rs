use super::readiness::{
    credential_access_policy, native_journal_keyring, native_withheld_tail_store,
};
use super::*;
#[cfg(test)]
use crate::application::workspace_internal::ProtectedProviderDependencyCapsule;
#[cfg(test)]
use runne_secure_store::ProviderCredentialId;
mod compose;
mod credential_reader;
mod credential_reconciliation;
mod dependencies;
mod enrollment_control;
#[cfg(any(test, feature = "test-support"))]
mod fixture_credentials;
mod input;
mod journal_bootstrap;
mod model_pin;
mod policy;
mod remote_context;
mod secondary_background;
mod service;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
mod tool_payload;
pub(crate) use input::DaemonCanonicalProviderComposition;
pub(super) use policy::*;
pub use service::DaemonCanonicalProviderService;

#[cfg(test)]
mod tests;
include!("composition/secondary_catalog_install.rs");
