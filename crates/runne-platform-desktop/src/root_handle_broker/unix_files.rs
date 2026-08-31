use std::path::{Component, PathBuf};

use super::files::{RootFileKind, RootFileEntry, entry};

pub(super) fn clone_root(root: &VerifiedRootHandle) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    verified_from_handle(root.handle.try_clone().map_err(|_| RootHandleBrokerError::Unavailable)?)
}

#[cfg(target_os = "linux")]
pub(super) fn list_relative(
    root: &NativeDirectoryHandle,
    path: &Path,
    limit: usize,
) -> Result<Vec<RootFileEntry>, RootHandleBrokerError> {
    let directory = open_directory_below(root, path)?;
    let mut buffer = Vec::with_capacity(8192);
    let mut iterator = RawDir::new(&directory, buffer.spare_capacity_mut());
    let mut entries = Vec::new();
    while let Some(item) = iterator.next() {
        let item = item.map_err(|_| RootHandleBrokerError::Unavailable)?;
        let name = item.file_name().to_str().map_err(|_| RootHandleBrokerError::Rejected)?;
        if name == "." || name == ".." { continue; }
        if entries.len() >= limit { return Err(RootHandleBrokerError::Rejected); }
        let opened = openat(
            &directory,
            item.file_name(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ).map_err(|_| RootHandleBrokerError::Rejected)?;
        let stat = fstat(&opened).map_err(|_| RootHandleBrokerError::Unavailable)?;
        let kind = if FileType::from_raw_mode(stat.st_mode).is_file() {
            RootFileKind::File
        } else if FileType::from_raw_mode(stat.st_mode).is_dir() {
            RootFileKind::Directory
        } else {
            return Err(RootHandleBrokerError::Rejected);
        };
        let relative_path = if path.as_os_str().is_empty() {
            name.to_owned()
        } else {
            format!("{}/{name}", path.display())
        };
        let size_bytes = u64::try_from(stat.st_size).map_err(|_| RootHandleBrokerError::Rejected)?;
        entries.push(entry(relative_path, kind, size_bytes));
    }
    entries.sort_by(|left, right| left.relative_path().cmp(right.relative_path()));
    Ok(entries)
}

#[cfg(target_os = "macos")]
pub(super) fn list_relative(
    root: &NativeDirectoryHandle,
    path: &Path,
    limit: usize,
) -> Result<Vec<RootFileEntry>, RootHandleBrokerError> {
    let directory = open_directory_below(root, path)?;
    let mut directory = nix::dir::Dir::from_fd(directory.into())
        .map_err(|_| RootHandleBrokerError::Unavailable)?;
    let mut entries = Vec::new();
    let names = directory
        .iter()
        .map(|item| {
            item.map_err(|_| RootHandleBrokerError::Unavailable)
                .and_then(|item| {
                    item.file_name()
                        .to_str()
                        .map(str::to_owned)
                        .map_err(|_| RootHandleBrokerError::Rejected)
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for name in names {
        if name == "." || name == ".." {
            continue;
        }
        if entries.len() >= limit {
            return Err(RootHandleBrokerError::Rejected);
        }
        let opened = openat(
            &directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RootHandleBrokerError::Rejected)?;
        let stat = fstat(&opened).map_err(|_| RootHandleBrokerError::Unavailable)?;
        let kind = if FileType::from_raw_mode(stat.st_mode).is_file() {
            RootFileKind::File
        } else if FileType::from_raw_mode(stat.st_mode).is_dir() {
            RootFileKind::Directory
        } else {
            return Err(RootHandleBrokerError::Rejected);
        };
        let relative_path = if path.as_os_str().is_empty() {
            name
        } else {
            format!("{}/{name}", path.display())
        };
        let size_bytes = u64::try_from(stat.st_size).map_err(|_| RootHandleBrokerError::Rejected)?;
        entries.push(entry(relative_path, kind, size_bytes));
    }
    entries.sort_by(|left, right| left.relative_path().cmp(right.relative_path()));
    Ok(entries)
}

pub(super) fn list_root(
    root: &NativeDirectoryHandle,
    limit: usize,
) -> Result<Vec<RootFileEntry>, RootHandleBrokerError> {
    list_relative(root, Path::new(""), limit)
}

pub(super) fn read_text_relative(
    root: &NativeDirectoryHandle,
    path: &Path,
    maximum_bytes: usize,
) -> Result<String, RootHandleBrokerError> {
    let file = open_file_below(root, path)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum_bytes).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| RootHandleBrokerError::Unavailable)?;
    if bytes.len() > maximum_bytes { return Err(RootHandleBrokerError::Rejected); }
    String::from_utf8(bytes).map_err(|_| RootHandleBrokerError::Rejected)
}

pub(super) fn open_directory_below(root: &NativeDirectoryHandle, path: &Path) -> Result<File, RootHandleBrokerError> {
    let mut current = File::from(
        openat(
            root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RootHandleBrokerError::Unavailable)?,
    );
    let root_device = fstat(&current).map_err(|_| RootHandleBrokerError::Unavailable)?.st_dev;
    for component in path.components() {
        let Component::Normal(component) = component else { return Err(RootHandleBrokerError::Rejected); };
        let opened = openat(&current, component, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|_| RootHandleBrokerError::Rejected)?;
        let stat = fstat(&opened).map_err(|_| RootHandleBrokerError::Unavailable)?;
        if !FileType::from_raw_mode(stat.st_mode).is_dir() || stat.st_dev != root_device { return Err(RootHandleBrokerError::Rejected); }
        current = File::from(opened);
    }
    Ok(current)
}

pub(super) fn open_file_below(root: &NativeDirectoryHandle, path: &Path) -> Result<File, RootHandleBrokerError> {
    let components = path.components().collect::<Vec<_>>();
    let (name, parents) = components.split_last().ok_or(RootHandleBrokerError::Rejected)?;
    let parent_path = parents.iter().fold(PathBuf::new(), |mut path, component| {
        path.push(component.as_os_str());
        path
    });
    let parent = open_directory_below(root, &parent_path)?;
    let Component::Normal(name) = name else { return Err(RootHandleBrokerError::Rejected); };
    let opened = openat(&parent, *name, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|_| RootHandleBrokerError::Rejected)?;
    let stat = fstat(&opened).map_err(|_| RootHandleBrokerError::Unavailable)?;
    FileType::from_raw_mode(stat.st_mode).is_file().then_some(File::from(opened)).ok_or(RootHandleBrokerError::Rejected)
}

fn file_identity_digest(file: &File) -> Result<[u8; 32], RootHandleBrokerError> {
    let stat = fstat(file).map_err(|_| RootHandleBrokerError::Unavailable)?;
    let mut digest = Sha256::new();
    #[cfg(target_os = "macos")]
    digest.update(i64::from(stat.st_dev).to_be_bytes());
    #[cfg(not(target_os = "macos"))]
    digest.update(stat.st_dev.to_be_bytes());
    digest.update((stat.st_ino as u64).to_be_bytes());
    Ok(digest.finalize().into())
}

fn content_digest(file: &File) -> Result<[u8; 32], RootHandleBrokerError> {
    let mut copy = file
        .try_clone()
        .map_err(|_| RootHandleBrokerError::Unavailable)?;
    copy.seek(SeekFrom::Start(0))
        .map_err(|_| RootHandleBrokerError::Unavailable)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = copy
            .read(&mut buffer)
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}
