#[cfg(any(test, all(unix, feature = "desktop-protected")))]
use std::sync::Arc;

#[cfg(any(test, all(unix, feature = "desktop-protected")))]
use runne_api::ProviderCredentialEnrollmentHostError;
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialEnrollmentMeasurementAuthority,
    CredentialMeasurementSnapshot, CredentialNativeEffectDisposition, CredentialOperationSnapshot,
    CredentialSecretClaimOffer, CredentialSecretPublication, IssuedCredentialTicketAttempt,
    ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
use zeroize::Zeroizing;

#[cfg(any(test, all(unix, feature = "desktop-protected")))]
use super::effect_authority::map_store;
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
mod claimed_effect;
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
mod effect_release;
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
pub(super) use claimed_effect::{AcceptedBrokerClaim, ClaimedBrokerEffect};
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
pub(crate) mod issue;
pub(super) mod pending;
#[cfg(all(unix, feature = "desktop-protected"))]
mod pending_writer;
#[cfg(all(unix, feature = "desktop-protected"))]
mod qualified_exchange;
#[cfg(all(target_os = "macos", feature = "desktop-protected"))]
pub(crate) use qualified_exchange::{FencedWriterExchange, QualifiedIssuedTicket};
#[cfg(all(unix, feature = "desktop-protected"))]
pub(super) use qualified_exchange::{QualifiedCredentialBrokerChannel, QualifiedIssueTransmission};
#[cfg(all(unix, feature = "desktop-protected"))]
mod qualified_control;
#[cfg(all(unix, feature = "desktop-protected"))]
mod qualified_issue;
#[cfg(all(test, unix, feature = "desktop-protected"))]
#[path = "broker/qualified_wiring_tests.rs"]
mod qualified_wiring_tests;
#[cfg(unix)]
pub(crate) mod rendezvous;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
pub(super) mod unix_linux;

#[cfg(all(unix, feature = "desktop-protected"))]
pub(super) mod unix;
#[cfg(all(target_os = "macos", feature = "desktop-protected"))]
pub(crate) use unix::MacOsCredentialBrokerChannel;
#[cfg(test)]
pub(crate) mod writer_session_test_support;

#[cfg(all(
    feature = "desktop-protected",
    any(all(test, unix), all(target_os = "macos", target_arch = "aarch64"))
))]
pub(crate) use pending::{AwaitingVerifiedWriter, PendingBrokerEndpointHandoff};
#[cfg(all(
    unix,
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
pub(crate) use pending_writer::VerifiedMacOsWriterWithDaemonKillCapability;
#[cfg(all(
    feature = "desktop-protected",
    any(all(test, unix), all(target_os = "macos", target_arch = "aarch64"))
))]
pub(crate) use pending_writer::VerifiedWriterAwaitingDaemonKillCapability;

/// Authenticated inherited control channel; Task 11 owns its platform adapters.
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
mod native;
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
pub(crate) use native::CredentialBrokerChannel;
#[cfg(any(test, all(unix, feature = "desktop-protected")))]
pub(super) use native::ProviderCredentialBroker;
#[cfg(test)]
pub(super) use native::secret_offer_matches_action;
