use super::*;
use crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin;
use runne_application::ports::PrincipalId;
use runne_domain::event::Actor;
use runne_domain::id::{ConversationId, WorkspaceId};
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};

fn origin(selected: Option<SelectedProviderProfile>) -> VerifiedTaskRunSubmitOrigin {
    let mut input = TaskRunInput::new("fixture prompt".into()).unwrap();
    if let Some(profile) = selected {
        input = input.with_selected_profile(profile).unwrap();
    }
    VerifiedTaskRunSubmitOrigin {
        conversation_id: ConversationId::from_bytes([1; 16]),
        workspace_id: WorkspaceId::from_bytes([2; 16]),
        project_id: None,
        input,
        principal_id: PrincipalId("fixture-principal".into()),
        actor: Actor::new("fixture-actor").unwrap(),
    }
}

#[test]
fn secondary_remote_source_requires_exact_submitted_profile() {
    let selected = SelectedProviderProfile::new("background/1".into(), [3; 32]).unwrap();
    let selected_origin = origin(Some(selected));
    assert!(
        verify_selected_profile(
            &selected_origin,
            "openai-background",
            "background/1",
            &[3; 32]
        )
        .is_ok()
    );
    assert!(
        verify_selected_profile(
            &selected_origin,
            "openai-background",
            "background/1",
            &[4; 32]
        )
        .is_err()
    );
    assert!(
        verify_selected_profile(&selected_origin, "openai-background", "primary/1", &[3; 32])
            .is_err()
    );
    assert!(
        verify_selected_profile(&origin(None), "openai-background", "background/1", &[3; 32])
            .is_err()
    );
}

#[test]
fn historical_unselected_primary_and_exact_selected_primary_remain_supported() {
    assert!(verify_selected_profile(&origin(None), "openai", "legacy-primary/1", &[7; 32]).is_ok());
    let profile = SelectedProviderProfile::new("primary/1".into(), [8; 32]).unwrap();
    assert!(
        verify_selected_profile(&origin(Some(profile)), "openai", "primary/1", &[8; 32]).is_ok()
    );
}
