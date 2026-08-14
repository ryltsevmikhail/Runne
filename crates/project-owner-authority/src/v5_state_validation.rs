//! Exact authenticated-state checks performed before every V5 admission CAS.

use crate::{
    AuthorityError, AuthorityStateSnapshot, DestinationAllowlistAdmissionScope,
    ReceiptV5AdmissionScope, RoleScopeFloor, RootAuthorityIdentity5D, V5AdmissionScope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptAdmissionPhase {
    NewlyAdmitted,
    ExistingSame,
}

pub fn receipt(
    state: &AuthorityStateSnapshot,
    scope: &ReceiptV5AdmissionScope,
) -> Result<ReceiptAdmissionPhase, AuthorityError> {
    let root = RootAuthorityIdentity5D {
        principal_id: scope.root_principal_id.clone(),
        controlling_account_id: scope.root_controlling_account_id.clone(),
        lane_id: scope.root_lane_id.clone(),
        key_id: scope.root_key_id.clone(),
        signature_profile_id: scope.root_signature_profile_id.clone(),
        public_key: scope.root_public_key,
        key_epoch: scope.root_key_epoch,
    };
    let floors = floors(&scope.transition_delegations, &scope.evidence_delegations);
    let phase = match state.active_receipt_generation {
        4 => ReceiptAdmissionPhase::NewlyAdmitted,
        5 => ReceiptAdmissionPhase::ExistingSame,
        _ => return Err(AuthorityError::PromotionBootstrapAdmissionConflict),
    };
    exact(
        state,
        scope.trust_generation,
        state.active_receipt_generation,
        scope.destination_allowlist_generation,
        &root,
        scope.root_revocation_epoch,
        &floors,
    )?;
    Ok(phase)
}

pub fn newly_admitted_state(
    state: &AuthorityStateSnapshot,
    receipt_generation: u64,
) -> Result<AuthorityStateSnapshot, AuthorityError> {
    let mut next = state.clone();
    next.durable_generation = next
        .durable_generation
        .checked_add(1)
        .ok_or(AuthorityError::PromotionBootstrapAdmissionConflict)?;
    next.active_receipt_generation = receipt_generation;
    Ok(next)
}

pub fn envelope(
    state: &AuthorityStateSnapshot,
    scope: &V5AdmissionScope,
) -> Result<(), AuthorityError> {
    exact(
        state,
        scope.trust_generation,
        5,
        scope.destination_allowlist_generation,
        &scope.root_identity,
        scope.root_revocation_epoch,
        &scope.role_scope_floors,
    )
}

pub fn allowlist(
    state: &AuthorityStateSnapshot,
    scope: &DestinationAllowlistAdmissionScope,
) -> Result<(), AuthorityError> {
    let root = RootAuthorityIdentity5D {
        principal_id: scope.root_principal_id.clone(),
        controlling_account_id: scope.root_controlling_account_id.clone(),
        lane_id: scope.root_lane_id.clone(),
        key_id: scope.root_key_id.clone(),
        signature_profile_id: scope.root_signature_profile_id.clone(),
        public_key: scope.root_public_key,
        key_epoch: scope.root_key_epoch,
    };
    exact(
        state,
        scope.trust_generation,
        5,
        scope.generation,
        &root,
        scope.root_revocation_epoch,
        &scope.role_scope_floors,
    )
}

pub fn floors(
    transition: &[crate::DelegationV2],
    evidence: &[crate::DelegationV2],
) -> Vec<RoleScopeFloor> {
    let mut values: Vec<_> = transition
        .iter()
        .chain(evidence)
        .map(|item| RoleScopeFloor {
            role: item.role.clone(),
            scope: item.scope.clone(),
            revocation_epoch: item.revocation_epoch,
        })
        .collect();
    values.sort();
    values
}

fn exact(
    state: &AuthorityStateSnapshot,
    trust_generation: u64,
    receipt_generation: u64,
    allowlist_generation: u64,
    root: &RootAuthorityIdentity5D,
    root_floor: u64,
    role_floors: &[RoleScopeFloor],
) -> Result<(), AuthorityError> {
    let mut actual_floors = state.role_scope_floors.clone();
    actual_floors.sort();
    if state.active_trust_generation != trust_generation
        || state.active_receipt_generation != receipt_generation
        || state.active_allowlist_generation != allowlist_generation
        || &state.root != root
        || state.root_revocation_floor != root_floor
        || actual_floors != role_floors
    {
        return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
    }
    Ok(())
}
