//! Closed permission-control transport. Authentication here never verifies consent.

mod auth;
mod codec;
mod consent;
mod context;
mod decode;
mod encode;
mod managed;
mod mode;
mod model;
mod native_auth;
mod result;
mod routing;
mod subject;
mod validation;

pub use auth::PermissionControlAuthenticatorV1;
pub use consent::{
    ModeOsAttestationV1, PermissionControlManagedConsentV1, PermissionControlModeConsentV1,
};
pub use context::PermissionControlContextV1;
pub use managed::{
    ManagedDecisionV1, ManagedPolicyV1, PermissionControlManagedChallengeV1,
    PermissionControlManagedRequestV1,
};
pub use mode::{
    PermissionControlModeChallengeV1, PermissionControlModeRequestV1, PermissionModeSelectionV1,
};
pub use model::{
    AuthenticatedPermissionControlFrameV1, PermissionControlDirectionV1, PermissionControlErrorV1,
    PermissionControlPayloadV1, PermissionControlPhaseV1, PermissionControlPurposeV1,
};
pub use native_auth::{PermissionControlNativeAuthenticatorV1, PermissionControlNativeErrorV1};
pub use result::{PermissionControlResultCodeV1, PermissionControlResultV1};
pub use routing::PermissionControlRoutingHintV1;
pub use subject::{PermissionControlSubjectErrorV1, permission_control_stable_subject_digest_v1};

#[cfg(test)]
mod routing_tests;
#[cfg(test)]
mod subject_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_adversarial;
#[cfg(test)]
mod tests_support;
