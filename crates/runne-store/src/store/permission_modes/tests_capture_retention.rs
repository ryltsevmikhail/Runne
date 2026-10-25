//! Capture retention, not native GO or consumed human-approval qualification.
#[path = "tests_capture_retention/ceremony.rs"]
mod ceremony;
#[path = "tests_capture_retention/fixture.rs"]
mod fixture;
#[path = "tests_capture_retention/target.rs"]
mod target;

use fixture::Fixture;
use runne_application::permission_modes::PermissionMode;

#[test]
fn same_mode_revision_preserves_current_prepared_capture() {
    let fixture = Fixture::new();
    ceremony::commit(&fixture, PermissionMode::RiskBased, 0);
    let (binding, capture, _prepared) = target::capture(&fixture);
    let identity = binding.assignment();
    assert_eq!(
        fixture
            .store
            .local_command_permission_stop_reason(identity, &binding)
            .unwrap(),
        None
    );
    let before = fixture
        .store
        .load_local_command_permission_capture(identity.taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(before, capture);

    ceremony::commit(&fixture, PermissionMode::RiskBased, 1);
    let selection = fixture
        .store
        .load_permission_mode_selection(&fixture.scope, &fixture.principal)
        .unwrap();
    assert_eq!(selection.authorization_revision, 2);
    ceremony::assert_same_policy(&fixture, &binding);
    assert_eq!(selection.selected_mode, binding.selection().selected_mode);
    assert_eq!(selection.preset_version, binding.selection().preset_version);
    assert_eq!(
        selection.expires_at_unix_ms,
        binding.selection().expires_at_unix_ms
    );
    let after = fixture
        .store
        .load_local_command_permission_capture(identity.taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        after, before,
        "mode commit must not rewrite immutable capture facts"
    );
    assert_eq!(
        fixture
            .store
            .local_command_permission_stop_reason(identity, &binding)
            .unwrap(),
        None,
        "compatible revision-only mode commit must retain the prepared capture, not blanket reason 2"
    );
}

#[test]
fn changed_trust_refuses_original_prepared_binding_before_capture() {
    use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustStatus};
    let fixture = Fixture::new();
    ceremony::commit(&fixture, PermissionMode::RiskBased, 0);
    let (binding, prepared) = target::prepare(&fixture);
    assert_eq!(
        fixture
            .store
            .load_local_command_permission_capture(binding.assignment().taskrun_id)
            .unwrap(),
        None
    );
    let current = fixture.trust.load(fixture.trust_id()).unwrap();
    fixture
        .trust
        .commit(
            fixture.trust_id(),
            ProjectTrustStatus::Untrusted,
            0,
            current.token(),
        )
        .unwrap();
    assert_eq!(
        fixture
            .store
            .capture_local_command_permission(&binding, prepared.observation()),
        Err(runne_application::ports::EventStoreError::CorruptData)
    );
    assert_eq!(
        fixture
            .store
            .load_local_command_permission_capture(binding.assignment().taskrun_id)
            .unwrap(),
        None
    );
}

#[test]
fn changed_mode_stops_current_prepared_capture() {
    let fixture = Fixture::new();
    ceremony::commit(&fixture, PermissionMode::RiskBased, 0);
    let (binding, _, _prepared) = target::capture(&fixture);
    ceremony::commit(&fixture, PermissionMode::AskAlways, 1);
    assert_eq!(
        fixture
            .store
            .local_command_permission_stop_reason(binding.assignment(), &binding)
            .unwrap(),
        Some(2)
    );
}
