use super::*;
use super::confirmation::confirmation_copy;

fn binding() -> runne_app_core::MutationAdmissionBinding {
    runne_app_core::MutationAdmissionBinding {
        runtime_identity_digest: [1; 32], principal_digest: [2; 32], gate_epoch: 3,
    }
}

#[tokio::test]
async fn committed_lease_drop_leaves_completion_to_task_port() {
    let manager = DestructiveIntentManager::new(std::time::Duration::from_secs(30)).unwrap();
    let now = std::time::Instant::now();
    let (reference, decision) = manager.issue("main", 7, binding(), [4; 32], now).unwrap();
    let completion = manager.consume(&reference, "main", 7, now).unwrap();
    assert!(decision.await.unwrap());
    let mut lease = DesktopConfirmationLease {
        intents: manager.clone(), reference: reference.clone(), binding: binding(),
        digest: [4; 32], decision: None, committed: false,
    };
    assert!(lease.try_commit());
    drop(lease);
    manager.clear_pending();
    manager.finish(&reference, Ok(()));
    assert!(completion.await.unwrap().is_ok());
}

#[test]
fn unpublished_operation_fails_before_native_confirmation() {
    let Err(error) = parse_destructive_operation("runtime_stop") else { panic!("unsupported command accepted") };
    assert_eq!(error.code, "COMMAND_CONTRACT_NOT_PUBLISHED");
}

#[test]
fn confirmation_copy_is_compact_and_redacts_runtime_identifiers() {
    let project_id = runne_app_core::CanonicalId::parse("018f2e3a-7000-7000-8000-000000000913").unwrap();
    let (title, message, confirm, cancel) = confirmation_copy(
        NativeConfirmationLocale::English,
        ProjectDestructiveOperation::Delete,
        project_id,
        "Selected folder",
        1,
    );
    assert_eq!(title, "Delete project?");
    assert_eq!(message, "Delete «Selected folder»?\n\n1 workspace will be affected.\nProject ref: …00000913");
    assert_eq!((confirm.as_str(), cancel.as_str()), ("Confirm", "Cancel"));
    assert!(!message.contains("version"));
    assert!(!message.contains(&project_id.to_string()));
}

#[test]
fn confirmation_copy_localizes_native_actions() {
    let project_id = runne_app_core::CanonicalId::parse("018f2e3a-7000-7000-8000-000000000913").unwrap();
    let (title, message, confirm, cancel) = confirmation_copy(
        NativeConfirmationLocale::Russian,
        ProjectDestructiveOperation::Archive,
        project_id,
        "Selected folder",
        2,
    );
    assert_eq!(title, "Архивировать проект?");
    assert!(message.contains("Архивировать «Selected folder»?"));
    assert!(message.contains("Будут затронуты 2 workspace."));
    assert_eq!((confirm.as_str(), cancel.as_str()), ("Подтвердить", "Отмена"));
}
