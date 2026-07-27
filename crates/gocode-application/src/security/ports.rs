//! Порты capability engine и durable grant projections.

use gocode_domain::{
    security::{AuthEpoch, CanonicalAction, GrantId, NormalizedResource, PrincipalIdentity},
    timestamp::Timestamp,
};

use super::{
    delegation::AttenuationPolicy,
    error::SecurityError,
    grant::{CapabilityGrant, GrantConstraints, GrantLifecycle, GrantScope},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequest {
    pub subject: PrincipalIdentity,
    pub action: CanonicalAction,
    pub resource: NormalizedResource,
    pub constraints: GrantConstraints,
    pub scope: GrantScope,
    pub auth_epoch: AuthEpoch,
    pub evaluated_at: Timestamp,
}

pub trait CapabilityEngine: Send + Sync {
    fn evaluate(&self, request: &CapabilityRequest) -> Result<CapabilityGrant, SecurityError>;
    fn validate_grant(
        &self,
        grant: &CapabilityGrant,
        request: &CapabilityRequest,
    ) -> Result<(), SecurityError>;
}

pub trait GrantStore: Send + Sync {
    fn get_grant(&self, grant_id: GrantId) -> Result<Option<CapabilityGrant>, SecurityError>;
    fn get_active(
        &self,
        subject: &PrincipalIdentity,
        action: &CanonicalAction,
        resource: &NormalizedResource,
    ) -> Result<Vec<CapabilityGrant>, SecurityError>;
    fn derive_child(
        &self,
        parent: &CapabilityGrant,
        attenuation: &AttenuationPolicy,
    ) -> Result<CapabilityGrant, SecurityError>;
    fn list_by_subject(
        &self,
        subject: &PrincipalIdentity,
    ) -> Result<Vec<CapabilityGrant>, SecurityError>;
}

pub trait GrantLifecycleStore: Send + Sync {
    fn get_lifecycle(&self, grant_id: GrantId) -> Result<Option<GrantLifecycle>, SecurityError>;
    fn get_active(&self, grant_id: GrantId) -> Result<Option<GrantLifecycle>, SecurityError>;
}
