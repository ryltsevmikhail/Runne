//! Проверка attenuation при создании дочернего grant.

use runne_domain::{
    security::{AuthEpoch, CanonicalAction, GrantId, NormalizedResource, PrincipalIdentity},
    timestamp::Timestamp,
};

use super::grant::{CapabilityGrant, GrantConstraints, GrantScope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttenuationPolicy {
    pub grant_id: GrantId,
    pub subject: PrincipalIdentity,
    pub action: CanonicalAction,
    pub resource: NormalizedResource,
    pub constraints: GrantConstraints,
    pub scope: GrantScope,
    pub expires_at: Timestamp,
    pub policy_revision: u64,
    pub auth_epoch: AuthEpoch,
    pub audit_correlation: String,
    pub issued_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttenuationError {
    ScopeNotSubset,
    ExpirationExceedsParent,
    ConstraintsWeakerThanParent,
    ActionNotCovered,
    ResourceNotContained,
    DelegationLimitExceeded,
    AuthEpochMismatch,
}

pub fn attenuate(
    parent: &CapabilityGrant,
    attenuation: &AttenuationPolicy,
) -> Result<CapabilityGrant, AttenuationError> {
    if !attenuation.scope.is_subset_of(&parent.scope) {
        return Err(AttenuationError::ScopeNotSubset);
    }
    if attenuation.expires_at > parent.expires_at {
        return Err(AttenuationError::ExpirationExceedsParent);
    }
    if !attenuation
        .constraints
        .is_at_least_as_strict_as(&parent.constraints)
    {
        return Err(AttenuationError::ConstraintsWeakerThanParent);
    }
    if !parent.covers_action(&attenuation.action) {
        return Err(AttenuationError::ActionNotCovered);
    }
    if !parent.covers_resource(&attenuation.resource) {
        return Err(AttenuationError::ResourceNotContained);
    }
    if parent.delegation_limit == 0 {
        return Err(AttenuationError::DelegationLimitExceeded);
    }
    if attenuation.auth_epoch != parent.auth_epoch {
        return Err(AttenuationError::AuthEpochMismatch);
    }

    Ok(CapabilityGrant {
        grant_id: attenuation.grant_id,
        subject: attenuation.subject.clone(),
        issuer: parent.subject.clone(),
        action: attenuation.action.clone(),
        resource: attenuation.resource.clone(),
        constraints: attenuation.constraints.clone(),
        scope: attenuation.scope.clone(),
        expires_at: attenuation.expires_at,
        delegation_limit: parent.delegation_limit - 1,
        policy_revision: attenuation.policy_revision,
        auth_epoch: attenuation.auth_epoch,
        audit_correlation: attenuation.audit_correlation.clone(),
        issued_at: attenuation.issued_at,
    })
}
