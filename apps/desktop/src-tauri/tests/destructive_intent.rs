#[test]
fn unpublished_destructive_operations_have_no_tauri_command() {
    let commands = include_str!("../src/lib_parts/commands.rs");
    let destructive = include_str!("../src/lib_parts/destructive_commands.rs");
    let run = include_str!("../src/lib_parts/run.rs");
    let handler = include_str!("../src/lib_parts/managed_task_run_handler.rs");

    assert!(run.contains(".invoke_handler(managed_task_run_handler!())"));
    assert!(handler.contains("            prepare_destructive_project_action,"));
    assert!(handler.contains("            dispatch_destructive_project_action,"));

    for name in [
        "respond_approval",
        "revoke_device",
        "unpair_device",
        "stop_runtime",
        "quit_runtime",
        "install_update",
        "reset_domain",
    ] {
        assert!(!commands.contains(&format!("fn {name}(")));
        assert!(!destructive.contains(&format!("fn {name}(")));
        assert!(!handler.contains(&format!("            {name},")));
    }
    assert!(destructive.contains("COMMAND_CONTRACT_NOT_PUBLISHED"));
}

#[test]
fn destructive_surface_has_one_native_port_and_no_public_prepared_continuation() {
    let destructive = include_str!("../src/lib_parts/destructive_commands.rs");
    let confirmation = include_str!("../src/lib_parts/destructive_commands/confirmation.rs");
    let app_core =
        include_str!("../../../../crates/runne-app-core/src/lib_parts/destructive_action.rs");
    let handler = include_str!("../src/lib_parts/managed_task_run_handler.rs");

    assert!(handler.contains("            prepare_destructive_project_action,"));
    assert!(handler.contains("            dispatch_destructive_project_action,"));
    assert_eq!(
        destructive
            .matches("impl DestructiveConfirmationPort for DesktopConfirmationPort")
            .count(),
        1
    );
    assert!(confirmation.contains(".parent(&parent)"));
    assert!(!app_core.contains("pub async fn prepare_destructive_project_action"));
    assert!(!app_core.contains("pub async fn dispatch_destructive_project_action"));
}
