use std::process::Command;

pub(super) fn launch_system_default_editor(
    root: &super::NativeDirectoryHandle,
    relative_path: &std::path::Path,
) -> Result<(), super::RootHandleBrokerError> {
    let target = root
        .open_editor_file_path(relative_path)
        .map_err(|_| super::RootHandleBrokerError::Rejected)?;
    Command::new("explorer.exe")
        .arg(target)
        .spawn()
        .map(|_| ())
        .map_err(|_| super::RootHandleBrokerError::Unavailable)
}
