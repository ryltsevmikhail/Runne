//! Pure selection/clock DATA only, not native admission or GO.
use super::super::retained_policy::selection_stop;
use super::fixture::Fixture;
use runne_application::permission_modes::{ModeSelection, PermissionMode};

#[test]
fn same_mode_cut_supports_no_cross_mode_pair() {
    let f = Fixture::new();
    let modes = [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ];
    let mut cross = 0;
    for original_mode in modes {
        for current_mode in modes {
            let mut original = ModeSelection::missing(f.scope.clone());
            original.selected_mode = original_mode;
            let mut current = original.clone();
            current.selected_mode = current_mode;
            current.authorization_revision = 99;
            let expected = if original_mode == current_mode {
                None
            } else {
                cross += 1;
                Some(2)
            };
            assert_eq!(selection_stop(&original, &current, 1001, 1000), expected);
        }
    }
    assert_eq!(cross, 6, "this unit deliberately retains SAME_MODE only");
}

#[test]
fn original_expiry_is_not_renewed_and_none_is_not_some() {
    let f = Fixture::new();
    let original = ModeSelection::missing(f.scope.clone());
    assert_eq!(selection_stop(&original, &original, 1000, 1000), Some(5));
    assert_eq!(selection_stop(&original, &original, 999, 1000), Some(5));
    assert_eq!(selection_stop(&original, &original, 1001, 1000), None);
    let mut changed = original.clone();
    changed.expires_at_unix_ms = Some(2000);
    assert_eq!(selection_stop(&original, &changed, 3000, 1000), Some(2));
    let mut original = original;
    original.expires_at_unix_ms = Some(1000);
    assert_eq!(selection_stop(&original, &original, 3000, 1000), Some(5));
    assert_eq!(selection_stop(&original, &changed, 3000, 1000), Some(2));
}
