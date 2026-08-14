use super::super::rc2;

pub struct Rc3AuthorizationParts {
    pub executor_principal: String,
    pub lane: String,
}

pub(super) fn parts(value: &rc2::OperationalIdentity) -> [&str; 5] {
    [
        &value.principal,
        &value.account,
        &value.lane,
        &value.key,
        &value.signature_profile,
    ]
}

#[cfg(any(test, feature = "fixture-only"))]
pub(super) fn owned_parts(value: &rc2::OperationalIdentity) -> [String; 5] {
    [
        value.principal.clone(),
        value.account.clone(),
        value.lane.clone(),
        value.key.clone(),
        value.signature_profile.clone(),
    ]
}
