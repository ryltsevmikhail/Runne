use runne_application::permission_modes::{
    CompositeScopeDigest, ContainmentStrategy, EffectiveModeHistoryState, NetworkState,
    PermissionMode, PermissionModeHistoryProjection,
};

use super::binding::command_and_proof;
use super::support::{Fixture, Storage};
use super::{begin, unix_ms};
use crate::store::permission_modes::model::PermissionModeCeremonyStatusV2;

// These file-backed regressions use the repository's explicit EchoV2 test verifier mock.
fn assert_receipt_reopens(strategy: ContainmentStrategy, network: NetworkState, expires: bool) {
    let mut fixture = Fixture::new(Storage::File);
    let mut request = fixture.request(PermissionMode::RiskBased, "receipt-codec-reopen");
    request.expires_at_unix_ms = expires.then(|| unix_ms() + 60_000);
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    let history = PermissionModeHistoryProjection {
        selected_mode: command.requested_mode,
        effective: EffectiveModeHistoryState::Ready {
            mode: command.requested_mode,
            preset_version: command.preset_version,
            scope_digest: CompositeScopeDigest::from_bytes([0x53; 32]),
            containment: strategy,
        },
        authorization_revision: command.expected_authorization_revision + 1,
        preset_version: command.preset_version,
        managed_policy_version: command.managed_policy_version,
        containment: Some(strategy),
        network_state: network,
        expires_at_unix_ms: command.expires_at_unix_ms,
    };
    let receipt = fixture
        .store()
        .commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history.clone(),
        )
        .unwrap();
    assert_eq!(receipt.projection, history.clone());
    fixture.reopen();
    assert_eq!(
        fixture
            .store()
            .commit_confirmed_permission_mode_v2(
                command.clone(),
                proof,
                &fixture.authority(),
                history,
            )
            .unwrap(),
        receipt
    );
    assert_eq!(
        fixture
            .store()
            .load_permission_mode_confirmation_status_v2(
                &request.scope,
                &fixture.principal,
                request.command_id,
            )
            .unwrap(),
        Some(PermissionModeCeremonyStatusV2::Committed(receipt))
    );
}

#[test]
fn workspace_bound_v1_receipt_reopens_with_brokered_network_and_expiry() {
    assert_receipt_reopens(
        ContainmentStrategy::WorkspaceBoundV1,
        NetworkState::Brokered,
        true,
    );
}

#[test]
fn same_user_v1_receipt_reopens_without_expiry() {
    assert_receipt_reopens(
        ContainmentStrategy::SameUserCompositeV1,
        NetworkState::BroadSameUser,
        false,
    );
}

#[test]
fn same_user_v2_receipt_reopens_with_unavailable_network_and_expiry() {
    assert_receipt_reopens(
        ContainmentStrategy::SameUserCompositeV2,
        NetworkState::Unavailable,
        true,
    );
}
