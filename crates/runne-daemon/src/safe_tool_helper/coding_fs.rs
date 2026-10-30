use super::*;
use crate::safe_tool_helper::platform;

pub(crate) fn open(root: &File, path: &str, flags: i32) -> Result<File, &'static str> {
    if !coding_arguments::valid_relative(path, true) {
        return Err("path_denied");
    }
    let name = CString::new(path).map_err(|_| "path_denied")?;
    let mode = if flags & libc::O_CREAT != 0 { 0o600 } else { 0 };
    platform::open_beneath(root, &name, flags, mode)
}

pub(crate) fn snapshot(
    root: &File,
    path: &str,
    directory: bool,
) -> Result<VersionV1, &'static str> {
    let file = open(root, path, O_PATH)?;
    if directory {
        identity(&file)?;
    } else if !regular_single(&file)? {
        return Err("target_denied");
    }
    let target = version(&file)?;
    if !directory && target.size > MAX_CONTENT as u64 {
        return Err("content_bound");
    }
    Ok(target)
}

pub(crate) fn capture(
    root: &File,
    tool: &str,
    path: &str,
) -> Result<Option<VersionV1>, &'static str> {
    if tool == "workspace.file.create_new" {
        let (parent, leaf) = path.rsplit_once('/').unwrap_or((".", path));
        let directory = open(root, parent, O_PATH | libc::O_DIRECTORY)?;
        let name = CString::new(leaf).map_err(|_| "path_denied")?;
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        let status = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status == 0 {
            return Err("target_exists");
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err("target_denied");
        }
        return Ok(None);
    }
    snapshot(
        root,
        path,
        matches!(
            tool,
            "workspace.files.list" | "workspace.files.search" | "workspace.command.run"
        ),
    )
    .map(Some)
}

pub(crate) fn bounded_read(root: &File, path: &str) -> Result<Vec<u8>, &'static str> {
    let file = open(root, path, libc::O_RDONLY | libc::O_NONBLOCK)?;
    if !regular_single(&file)? {
        return Err("target_denied");
    }
    let before = version(&file)?;
    let bytes = read_bounded(
        &file,
        usize::try_from(before.size).map_err(|_| "content_bound")?,
    )?;
    if before != version(&file)? {
        return Err("target_changed");
    }
    Ok(bytes)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn namespace_root(root: &File) -> Result<File, &'static str> {
    platform::namespace_root(root)
}

/// Returns the workspace path backing a pinned root descriptor.
#[cfg(target_os = "macos")]
pub(crate) fn pinned_path(root: &File) -> Result<std::path::PathBuf, &'static str> {
    platform::pinned_path(root)
}
