#[test]
fn picker_ipc_has_no_raw_path_or_renderer_dialog_capability() {
    let commands = include_str!("../src/lib_parts/commands.rs");
    let summaries = include_str!("../../../../crates/app-core/src/lib_parts/snapshots.rs");
    let renderer =
        include_str!("../../src/features/open-local-project/model/open-local-project.ts");
    let projects = include_str!("../../src/entities/project/api/projects.ts");
    let capability = include_str!("../capabilities/main.json");

    assert!(commands.contains("fn request_directory_selection"));
    assert!(commands.contains("fn prepare_selected_workspace"));
    assert!(!commands.contains("fn open_local_project"));
    assert!(!commands.contains("path: String"));
    assert!(commands.contains("project_id: String"));
    assert!(!summaries.contains("pub path:"));
    assert!(!summaries.contains("pub id: i64"));
    assert!(!projects.contains("readonly path:"));
    assert!(!projects.contains("readonly id:"));
    assert!(!renderer.contains("@tauri-apps/plugin-dialog"));
    assert!(!renderer.contains("rendererInstanceId"));
    assert!(!capability.contains("dialog:allow-open"));
}

#[test]
fn production_ipc_does_not_register_numeric_project_conversation_commands() {
    let run = include_str!("../src/lib_parts/run.rs");
    let commands = include_str!("../src/lib_parts/commands.rs");

    for command in [
        "open_project_conversation",
        "resync_project_conversation",
        "send_project_message",
        "subscribe_project_conversation",
    ] {
        assert!(
            !run.contains(command),
            "numeric command remains registered: {command}"
        );
    }
    assert!(!commands.contains("project_id: i64"));
}
