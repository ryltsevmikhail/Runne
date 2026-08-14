//! Validation of authenticated durable admission result state.

use crate::{
    AuthorityError, DurableAdmission, ExistingSameReceiptV5, NewlyAdmittedReceiptV5,
    PersistedAdmission,
};

pub fn receipt_new(
    result: &NewlyAdmittedReceiptV5,
    persisted: &PersistedAdmission,
    newly_admitted: &crate::AuthorityStateSnapshot,
) -> Result<(), AuthorityError> {
    if &result.persisted != persisted || &result.state != newly_admitted {
        return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
    }
    Ok(())
}

pub fn receipt_existing(
    result: &ExistingSameReceiptV5,
    persisted: &PersistedAdmission,
    expected: &crate::AuthorityStateSnapshot,
) -> Result<(), AuthorityError> {
    if &result.persisted != persisted || &result.state != expected {
        return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
    }
    Ok(())
}

pub fn unchanged_generations(
    result: &DurableAdmission,
    persisted: &PersistedAdmission,
    expected: &crate::AuthorityStateSnapshot,
    newly_admitted: &crate::AuthorityStateSnapshot,
) -> Result<(), AuthorityError> {
    require_persisted(result, persisted)?;
    match result {
        DurableAdmission::NewlyAdmitted { state, .. } if state == newly_admitted => Ok(()),
        DurableAdmission::ExistingSame { state, .. } if state == expected => Ok(()),
        _ => Err(AuthorityError::PromotionBootstrapAdmissionConflict),
    }
}

fn require_persisted(
    result: &DurableAdmission,
    expected: &PersistedAdmission,
) -> Result<(), AuthorityError> {
    if result.persisted() != expected {
        return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
    }
    Ok(())
}
