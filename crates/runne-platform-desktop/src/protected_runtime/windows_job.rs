// Job-object ownership for the Windows bundled runtime process tree.

fn assign_kill_on_close_job(
    child: &Child,
) -> Result<OwnedHandle, ProtectedBundledRuntimeError> {
    runne_windows_native_handle::assign_kill_on_close_job(child)
        .map_err(|_| ProtectedBundledRuntimeError::SpawnFailed)
}
