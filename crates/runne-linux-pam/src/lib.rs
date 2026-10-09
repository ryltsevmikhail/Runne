//! Linux PAM reauthentication, available to a native host but not activated by transport.
#![deny(unsafe_code)]
#![cfg(target_os = "linux")]

mod conversation;
mod ffi;
mod identity;
mod response_buffer;
mod transaction;
mod types;
mod verified_facts;

pub use conversation::{PamConversationHandler, PamMessageKind};
pub use transaction::reauthenticate;
pub use types::{
    FreshOsReauthentication, MAX_REAUTH_WINDOW, PamCancellation, PamInteractionError,
    ReauthenticationError, validate_deadline,
};
pub use verified_facts::VerifiedPamFacts;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_conversation;
#[cfg(test)]
mod tests_facts;
