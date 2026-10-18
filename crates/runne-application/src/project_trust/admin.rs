//! Unpublished typed ports for the same-sidecar managed-policy administrator.
//!
//! This module defines no production verifier. The daemon must pin one trusted
//! implementation before any administrative flow can be activated.

#[path = "admin/authority.rs"]
mod authority;
#[path = "admin/digest.rs"]
mod digest;
#[path = "admin/digest_encoding.rs"]
mod digest_encoding;
#[path = "admin/model.rs"]
mod model;
#[path = "admin/ports.rs"]
mod ports;
#[path = "admin/verification.rs"]
mod verification;

#[cfg(test)]
#[path = "admin/tests.rs"]
mod tests;

pub use authority::{
    PolicyAdminAuthoritySource, PolicyAdminAuthorityVerifier, PolicyAdminBootstrapVerifier,
    verify_policy_admin_bootstrap, with_verified_policy_admin,
};
pub use digest::{
    ManagedPolicyCommandV1, ReservedManagedPolicyCommandV1, managed_policy_command_digest_v1,
    managed_policy_request_digest_v1, policy_admin_session_binding_digest,
    policy_admin_stable_identity_digest,
};
pub use model::{
    AdminError, AuthenticatedPolicyAdminSubject, CurrentPolicyAdmin, ManagedPolicyAdministratorV1,
    PolicyAdminBootstrapEvidence, PolicyAdminSessionBinding, VerifiedPolicyAdminAuthorityFacts,
    VerifiedPolicyAdminBootstrap,
};
pub use ports::{ManagedPolicyAdminReceipt, ManagedPolicyCommandState, ManagedPolicyRoleState};
pub use verification::{
    ManagedPolicyConsentBindingV1, ManagedPolicyConsentVerifierV1, VerifiedManagedPolicyConsentV1,
    verify_managed_policy_consent_v1,
};
