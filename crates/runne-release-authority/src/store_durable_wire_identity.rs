use super::{AuthorityError, IdentityWire};

pub(super) fn into_identity(
    x: &IdentityWire,
) -> Result<crate::StageIssuerIdentity, AuthorityError> {
    for value in [&x.principal, &x.account, &x.lane, &x.signature_profile] {
        if !runne_promotion_contracts::canonical_id(value) {
            return Err(AuthorityError::NonCanonicalPayload);
        }
    }
    super::d(&x.key)?;
    Ok(crate::StageIssuerIdentity::durable(
        x.principal.clone(),
        x.account.clone(),
        x.lane.clone(),
        x.key.clone(),
        x.signature_profile.clone(),
    ))
}
