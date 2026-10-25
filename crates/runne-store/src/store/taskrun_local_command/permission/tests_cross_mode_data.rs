//! Pure conditional proof/selection DATA; no trusted receipt, native auth or GO.
use super::{AdmissionKind, VerifiedOriginalAdmission};
use crate::store::taskrun_local_command::permission::retained_policy::selection_stop_for_admission;
use runne_application::{permission_modes::*, ports::RuntimeAuthorityId};

fn selection(mode: PermissionMode) -> ModeSelection {
    let mut value = ModeSelection::missing(PermissionScope {
        runtime_authority_id: RuntimeAuthorityId("data-only-runtime".into()),
        principal_id: runne_api::ApiPrincipalId::new("data-only-human").unwrap(),
        workspace_id: runne_domain::id::WorkspaceId::from_bytes([1; 16]),
    });
    value.selected_mode = mode;
    value.authorization_revision = 1; // Conditional DATA receipt-era revision, not a receipt.
    value
}

#[test]
fn data_missing_selection_receipt_cannot_retain_cross_mode_human() {
    let original = selection(PermissionMode::RiskBased);
    let mut current = selection(PermissionMode::AskAlways);
    current.authorization_revision = 0; // Actual missing-row projection, no command receipt.
    let human = VerifiedOriginalAdmission {
        kind: AdmissionKind::Human,
        expires_at: 1001,
    };
    assert_eq!(
        selection_stop_for_admission(&original, &current, 1001, 1000, Some(&human)),
        Some(2)
    );
}

#[test]
fn data_six_human_pairs_require_live_original_not_auto_or_pending() {
    let modes = [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ];
    let mut pairs = 0;
    for old in modes {
        for new in modes {
            if old == new {
                continue;
            }
            let original = selection(old);
            let current = selection(new);
            for kind in [
                AdmissionKind::Pending,
                AdmissionKind::Auto,
                AdmissionKind::Human,
            ] {
                // Conditional DATA only, not a way to construct production proof evidence.
                let data = VerifiedOriginalAdmission {
                    kind,
                    expires_at: 1001,
                };
                let expected = if kind == AdmissionKind::Human {
                    None
                } else {
                    Some(2)
                };
                assert_eq!(
                    selection_stop_for_admission(&original, &current, 1001, 1000, Some(&data)),
                    expected
                );
                assert_eq!(
                    selection_stop_for_admission(&original, &current, 1001, 1001, Some(&data)),
                    Some(5)
                );
                let mut extended = current.clone();
                extended.expires_at_unix_ms = Some(2000);
                assert_eq!(
                    selection_stop_for_admission(&original, &extended, 1001, 1000, Some(&data)),
                    Some(2)
                );
                let mut other = current.clone();
                other.scope.principal_id = runne_api::ApiPrincipalId::new("other-human").unwrap();
                assert_eq!(
                    selection_stop_for_admission(&original, &other, 1001, 1000, Some(&data)),
                    Some(2)
                );
            }
            pairs += 1;
        }
    }
    assert_eq!(pairs, 6);
}

#[test]
fn data_auto_full_access_same_mode_is_unchanged_and_historical_human_is_not_live() {
    let full = selection(PermissionMode::FullAccess);
    let auto = VerifiedOriginalAdmission {
        kind: AdmissionKind::Auto,
        expires_at: 1001,
    };
    assert_eq!(
        selection_stop_for_admission(&full, &full, 1001, 1000, Some(&auto)),
        None
    );
    let historic = VerifiedOriginalAdmission {
        kind: AdmissionKind::Human,
        expires_at: 1000,
    };
    assert!(!historic.live_human(1000));
    assert_eq!(
        selection_stop_for_admission(&full, &full, 1000, 1000, Some(&historic)),
        Some(5)
    );
}
