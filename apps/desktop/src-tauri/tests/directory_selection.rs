#[test]
fn picker_ipc_has_no_raw_path_or_renderer_dialog_capability() {
    let commands = include_str!("../src/lib_parts/commands.rs");
    let renderer =
        include_str!("../../src/features/open-local-project/model/open-local-project.ts");
    let capability = include_str!("../capabilities/main.json");

    assert!(commands.contains("fn request_directory_selection"));
    assert!(commands.contains("fn prepare_selected_workspace"));
    assert!(!commands.contains("fn open_local_project"));
    assert!(!commands.contains("path: String"));
    assert!(!renderer.contains("@tauri-apps/plugin-dialog"));
    assert!(!renderer.contains("rendererInstanceId"));
    assert!(!capability.contains("dialog:allow-open"));
}
