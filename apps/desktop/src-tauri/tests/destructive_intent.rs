#[test]
fn unpublished_destructive_operations_have_no_tauri_command() {
    let commands = include_str!("../src/lib_parts/commands.rs");
    let destructive = include_str!("../src/lib_parts/destructive_commands.rs");
    let run = include_str!("../src/lib_parts/run.rs");

    for name in [
        "cancel_task_run",
        "respond_approval",
        "revoke_device",
        "unpair_device",
        "stop_runtime",
        "quit_runtime",
        "install_update",
        "reset_domain",
    ] {
        assert!(!commands.contains(&format!("fn {name}")));
        assert!(!destructive.contains(&format!("fn {name}")));
        assert!(!run.contains(name));
    }
    assert!(destructive.contains("COMMAND_CONTRACT_NOT_PUBLISHED"));
}

#[test]
fn destructive_surface_has_one_native_port_and_no_public_prepared_continuation() {
    let destructive = include_str!("../src/lib_parts/destructive_commands.rs");
    let app_core =
        include_str!("../../../../crates/runne-app-core/src/lib_parts/destructive_action.rs");

    assert_eq!(
        destructive
            .matches("impl DestructiveConfirmationPort for DesktopConfirmationPort")
            .count(),
        1
    );
    assert!(destructive.contains(".parent(&parent)"));
    assert!(!app_core.contains("pub async fn prepare_destructive_project_action"));
    assert!(!app_core.contains("pub async fn dispatch_destructive_project_action"));
}
