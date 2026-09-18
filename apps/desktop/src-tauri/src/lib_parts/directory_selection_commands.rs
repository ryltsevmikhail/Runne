// Directory-selection commands. Split from `commands.rs` to honor the
// 300-line source limit; included right after it in `lib.rs`.

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn request_directory_selection(
    window: WebviewWindow,
    selections: State<'_, DirectorySelectionManager>,
    renderer_generation: u64,
    request_id: String,
) -> Result<Option<DirectorySelectionResponse>, IpcError> {
    let label = window.label();
    if !window.is_focused().map_err(|_| IpcError { code: "directory_selection_rejected" })?
        || selections.renderer_generations().current(label).ok() != Some(renderer_generation)
    {
        return Err(IpcError { code: "directory_selection_rejected" });
    }
    let picker = selections.reserve_picker(label, renderer_generation)
        .map_err(|_| IpcError { code: "directory_selection_rejected" })?;
    // The dialog future must run off the main thread, and its result must be
    // collected through the blocking portal dialog: on Linux the xdg-portal
    // backend closes the chooser without ever invoking the async callback
    // (verified end-to-end), which would leave the lease hanging forever.
    let dialog_window = window.clone();
    let selected = tauri::async_runtime::spawn_blocking(move || {
        dialog_window
            .app_handle()
            .dialog()
            .file()
            .set_parent(&dialog_window)
            .set_title("Open local project")
            .blocking_pick_folder()
    })
    .await
    .map_err(|_| IpcError { code: "directory_selection_rejected" })?;
    let _picker = picker;
    let Some(selected) = selected else { return Ok(None) };
    // On Wayland the compositor restores parent focus only a few frames
    // after the portal dialog closes; allow a bounded settle window instead
    // of rejecting the user's selection outright. The later focus checks in
    // prepare/open still gate every state mutation.
    let mut focused = window
        .is_focused()
        .map_err(|_| IpcError { code: "directory_selection_rejected" })?;
    for _ in 0..20 {
        if focused {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        focused = window
            .is_focused()
            .map_err(|_| IpcError { code: "directory_selection_rejected" })?;
    }
    if !focused
        || selections.renderer_generations().current(label).ok() != Some(renderer_generation)
    {
        return Err(IpcError { code: "directory_selection_rejected" });
    }
    let path = std::fs::canonicalize(
        &selected.into_path().map_err(|_| IpcError { code: "directory_selection_rejected" })?,
    )
    .map_err(|_| IpcError { code: "directory_selection_rejected" })?;
    let root = VerifiedRootHandle::open(&path)
        .map_err(|_| IpcError { code: "directory_selection_rejected" })?;
    if !window.is_focused().map_err(|_| IpcError { code: "directory_selection_rejected" })? {
        return Err(IpcError { code: "directory_selection_rejected" });
    }
    selections
        .issue(label, renderer_generation, &request_id, root, std::time::Instant::now())
        .map(DirectorySelectionResponse::new)
        .map(Some)
        .map_err(|_| IpcError { code: "directory_selection_rejected" })
}
