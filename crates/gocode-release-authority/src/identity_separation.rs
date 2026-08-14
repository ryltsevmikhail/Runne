use super::{AuthorityError, CanonicalPayloadKind, VerifiedStagePayload};

/// Verify RC2 operational credentials are distinct from verified stage issuers.
///
/// # Errors
/// Returns an error for incorrect stage kinds, binding, or identity separation.
pub fn verify_rc2_operation_separation(
    rc1: &VerifiedStagePayload,
    rc2: &VerifiedStagePayload,
) -> Result<(), AuthorityError> {
    if [rc1.kind(), rc2.kind()]
        != [
            CanonicalPayloadKind::Rc1Decision,
            CanonicalPayloadKind::Rc2Authorization,
        ]
    {
        return Err(AuthorityError::BindingMismatch);
    }
    if rc1.root() != rc2.root() {
        return Err(AuthorityError::BindingMismatch);
    }
    let issuers = [rc1.root(), rc1.issuer(), rc2.issuer()];
    let operations = rc2
        .inspected()
        .rc2_operational_identities()
        .ok_or(AuthorityError::BindingMismatch)?;
    let mut dimensions = [
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
    ];
    for issuer in issuers {
        for (set, value) in dimensions.iter_mut().zip([
            issuer.principal_id(),
            issuer.account_id(),
            issuer.lane_id(),
            issuer.key_id(),
            issuer.signature_profile_id(),
        ]) {
            if !set.insert(value) {
                return Err(AuthorityError::IdentitySeparationViolation);
            }
        }
    }
    for operation in operations {
        for (set, value) in dimensions.iter_mut().zip(operation) {
            if !set.insert(value) {
                return Err(AuthorityError::IdentitySeparationViolation);
            }
        }
    }
    Ok(())
}

/// Verify that RC3's issuer and executor dimensions are disjoint from every prior authority.
///
/// # Errors
/// Returns an error unless all RC1, RC2, and RC3 credentials share one root and keep their
/// applicable identity dimensions disjoint.
pub fn verify_rc3_operation_separation(
    rc1: &VerifiedStagePayload,
    rc2: &VerifiedStagePayload,
    rc3: &VerifiedStagePayload,
) -> Result<(), AuthorityError> {
    if [rc1.kind(), rc2.kind(), rc3.kind()]
        != [
            CanonicalPayloadKind::Rc1Decision,
            CanonicalPayloadKind::Rc2Authorization,
            CanonicalPayloadKind::Rc3Authorization,
        ]
        || rc1.root() != rc2.root()
        || rc1.root() != rc3.root()
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let mut dimensions = [
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
    ];
    for issuer in [rc1.root(), rc1.issuer(), rc2.issuer(), rc3.issuer()] {
        for (set, value) in dimensions.iter_mut().zip([
            issuer.principal_id(),
            issuer.account_id(),
            issuer.lane_id(),
            issuer.key_id(),
            issuer.signature_profile_id(),
        ]) {
            if !set.insert(value) {
                return Err(AuthorityError::IdentitySeparationViolation);
            }
        }
    }
    for operation in rc2
        .inspected()
        .rc2_operational_identities()
        .ok_or(AuthorityError::BindingMismatch)?
    {
        for (set, value) in dimensions.iter_mut().zip(operation) {
            if !set.insert(value) {
                return Err(AuthorityError::IdentitySeparationViolation);
            }
        }
    }
    let rc3_operation = rc3
        .inspected()
        .rc3_authorization()
        .ok_or(AuthorityError::BindingMismatch)?;
    if !dimensions[0].insert(&rc3_operation.executor_principal)
        || !dimensions[2].insert(&rc3_operation.lane)
    {
        return Err(AuthorityError::IdentitySeparationViolation);
    }
    Ok(())
}
