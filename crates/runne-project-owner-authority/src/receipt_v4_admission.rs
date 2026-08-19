//! Trusted-context admission for prevalidated promotion bootstrap `/4` values.

use crate::{
    AuthorityError, PrevalidatedPromotionBootstrapV4, PromotionBootstrapAdmission,
    PromotionBootstrapVerificationContext, VerifiedPromotionBootstrap,
    receipt_v4::verified_bootstrap_with_root,
};

/// Admit a cryptographically prevalidated promotion bootstrap `/4`.
///
/// # Errors
/// Returns an error when trusted profile, state, or atomic recovery differs.
pub fn admit_prevalidated_promotion_bootstrap_v4(
    value: PrevalidatedPromotionBootstrapV4,
    context: &dyn PromotionBootstrapVerificationContext,
) -> Result<VerifiedPromotionBootstrap, AuthorityError> {
    if context
        .authority_store_profile()
        .map_err(|_| AuthorityError::PromotionBootstrapVerificationContextRequired)?
        != value.scope.authority_store_profile()
    {
        return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
    }
    let expected = context.read_state().map_err(|error| match error {
        AuthorityError::PromotionBootstrapVerificationContextRequired => error,
        _ => AuthorityError::PromotionBootstrapVerificationContextRequired,
    })?;
    match context
        .admit_or_recover_bootstrap(
            &expected,
            value.receipt.project_owner_authority_receipt_sha256,
            &value.scope,
            &value.validity,
        )
        .map_err(|error| match error {
            AuthorityError::StaleOrRevokedPromotionBootstrap
            | AuthorityError::PromotionBootstrapAdmissionConflict => error,
            _ => AuthorityError::PromotionBootstrapVerificationContextRequired,
        })? {
        PromotionBootstrapAdmission::NewlyAdmitted | PromotionBootstrapAdmission::ExistingSame => {}
    }
    let bindings = crate::PromotionBootstrapBindings::from_bootstrap(&value.receipt.unsigned);
    Ok(verified_bootstrap_with_root(
        value.receipt.project_owner_authority_receipt_sha256,
        value.receipt.unsigned.delegations,
        value.root_public_key,
        value.receipt.unsigned.subject,
        crate::VerifiedStageIssuer {
            principal: value.receipt.unsigned.root_principal_id,
            account: value.receipt.unsigned.root_controlling_account_id,
            lane: value.receipt.unsigned.root_lane_id,
            key: value.receipt.unsigned.key_id,
            signature_profile: value.receipt.unsigned.root_signature_profile_id,
        },
        value.validity,
        value.scope,
        bindings,
    ))
}
