use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::Component;

use rustix::fs::{FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, mkdirat, openat};
use rustix::process::{geteuid, getuid};

struct LinuxPermissionRecoveryIndex {
    state_dir: PathBuf,
}

impl LinuxPermissionRecoveryIndex {
    const fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }

    fn open_intents_root(
        &self,
        create: bool,
    ) -> Result<Option<rustix::fd::OwnedFd>, RecoveryError> {
        if !self.state_dir.is_absolute() || getuid() != geteuid() {
            return Err(RecoveryError::Io);
        }
        let mut current = openat(
            rustix::fs::CWD,
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| RecoveryError::Io)?;
        validate_ancestor_directory(&current)?;
        for component in self.state_dir.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = name.to_str().ok_or(RecoveryError::Io)?;
                    let Some(next) = open_directory(&current, name, create, false)? else {
                        return Ok(None);
                    };
                    validate_ancestor_directory(&next)?;
                    current = next;
                }
                _ => return Err(RecoveryError::Io),
            }
        }
        for name in ["runne", "cli", "permission-intents"] {
            let Some(next) = open_directory(&current, name, create, true)? else {
                return Ok(None);
            };
            current = next;
        }
        Ok(Some(current))
    }
}

impl PermissionRecoveryIndex for LinuxPermissionRecoveryIndex {
    fn read_existing(
        &self,
        expected_scope: &str,
        command_id: CanonicalId,
    ) -> Result<Option<Vec<u8>>, RecoveryError> {
        canonical_digest(expected_scope)?;
        let Some(root) = self.open_intents_root(false)? else {
            return Ok(None);
        };
        find_command_record(&root, command_id)
    }

    fn create_exclusive(
        &self,
        scope_digest: &str,
        command_id: CanonicalId,
        record: &[u8],
    ) -> Result<RecordCreateResult, RecoveryError> {
        canonical_digest(scope_digest)?;
        if record.is_empty() || record.len() > MAX_RECOVERY_RECORD_BYTES {
            return Err(RecoveryError::Io);
        }
        let root = self.open_intents_root(true)?.ok_or(RecoveryError::Io)?;
        flock(&root, FlockOperation::LockExclusive).map_err(|_| RecoveryError::Io)?;
        if let Some(existing) = find_command_record(&root, command_id)? {
            return Ok(RecordCreateResult::Existing(existing));
        }
        let scope = open_directory(&root, scope_digest, true, true)?.ok_or(RecoveryError::Io)?;
        let file_name = format!("{command_id}.json");
        let fd = match openat(
            &scope,
            &file_name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::from(0o600),
        ) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::EXIST => {
                let existing = read_record_at(&scope, &file_name)?.ok_or(RecoveryError::Io)?;
                validate_record_location(&existing, scope_digest, command_id)?;
                return Ok(RecordCreateResult::Existing(existing));
            }
            Err(_) => return Err(RecoveryError::Io),
        };
        validate_record_file(&fd)?;
        let mut file = File::from(fd);
        file.write_all(record).map_err(|_| RecoveryError::Io)?;
        file.sync_all().map_err(|_| RecoveryError::Io)?;
        fsync(&scope).map_err(|_| RecoveryError::Io)?;
        Ok(RecordCreateResult::DurableCreated)
    }
}

fn find_command_record(
    root: &rustix::fd::OwnedFd,
    command_id: CanonicalId,
) -> Result<Option<Vec<u8>>, RecoveryError> {
    let path = format!("/proc/self/fd/{}", root.as_raw_fd());
    let entries = std::fs::read_dir(path).map_err(|_| RecoveryError::Io)?;
    let file_name = format!("{command_id}.json");
    let mut found = None;
    let mut scanned = 0;
    for entry in entries {
        scanned += 1;
        if scanned > 4096 {
            return Err(RecoveryError::Io);
        }
        let entry = entry.map_err(|_| RecoveryError::Io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(RecoveryError::Corrupt)?;
        canonical_digest(name).map_err(|_| RecoveryError::Corrupt)?;
        let scope = openat(
            root,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RecoveryError::Io)?;
        validate_private_directory(&scope)?;
        if let Some(bytes) = read_record_at(&scope, &file_name)? {
            validate_record_location(&bytes, name, command_id)?;
            if found.is_some() {
                return Err(RecoveryError::Corrupt);
            }
            found = Some(bytes);
        }
    }
    Ok(found)
}

fn validate_record_location(
    bytes: &[u8],
    scope_digest: &str,
    command_id: CanonicalId,
) -> Result<(), RecoveryError> {
    let valid_location = match decode_any_command_record(bytes)? {
        RecoveredCommandRecord::PermissionMode(record) => {
            record.scope_digest == scope_digest && record.command_id == command_id
        }
        RecoveredCommandRecord::ApprovalDecision(record) => {
            record.scope_digest == scope_digest && record.command_id == command_id
        }
    };
    if !valid_location {
        return Err(RecoveryError::Corrupt);
    }
    Ok(())
}

fn read_record_at(
    scope: &rustix::fd::OwnedFd,
    file_name: &str,
) -> Result<Option<Vec<u8>>, RecoveryError> {
    let fd = match openat(
        scope,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(RecoveryError::Io),
    };
    validate_record_file(&fd)?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take((MAX_RECOVERY_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RecoveryError::Io)?;
    if bytes.is_empty() || bytes.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(RecoveryError::Corrupt);
    }
    Ok(Some(bytes))
}

fn open_directory(
    parent: &rustix::fd::OwnedFd,
    name: &str,
    create: bool,
    private: bool,
) -> Result<Option<rustix::fd::OwnedFd>, RecoveryError> {
    open_directory_with_sync(parent, name, create, private, |parent| {
        fsync(parent).map_err(|_| RecoveryError::Io)
    })
}

fn open_directory_with_sync(
    parent: &rustix::fd::OwnedFd,
    name: &str,
    create: bool,
    private: bool,
    sync_parent: impl FnOnce(&rustix::fd::OwnedFd) -> Result<(), RecoveryError>,
) -> Result<Option<rustix::fd::OwnedFd>, RecoveryError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = match openat(parent, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::NOENT && !create => return Ok(None),
        Err(error) if error == rustix::io::Errno::NOENT => {
            match mkdirat(parent, name, Mode::from(0o700)) {
                Ok(()) => {}
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(_) => return Err(RecoveryError::Io),
            }
            openat(parent, name, flags, Mode::empty()).map_err(|_| RecoveryError::Io)?
        }
        Err(_) => return Err(RecoveryError::Io),
    };
    if private {
        validate_private_directory(&fd)?;
    } else {
        validate_ancestor_directory(&fd)?;
    }
    if create {
        sync_parent(parent)?;
    }
    Ok(Some(fd))
}

fn validate_ancestor_directory(fd: &rustix::fd::OwnedFd) -> Result<(), RecoveryError> {
    let stat = fstat(fd).map_err(|_| RecoveryError::Io)?;
    let owner = geteuid().as_raw();
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != owner)
        || stat.st_mode & 0o022 != 0
    {
        return Err(RecoveryError::Io);
    }
    Ok(())
}

fn validate_private_directory(fd: &rustix::fd::OwnedFd) -> Result<(), RecoveryError> {
    let stat = fstat(fd).map_err(|_| RecoveryError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(RecoveryError::Io);
    }
    Ok(())
}

fn validate_record_file(fd: &rustix::fd::OwnedFd) -> Result<(), RecoveryError> {
    let stat = fstat(fd).map_err(|_| RecoveryError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size < 0
    {
        return Err(RecoveryError::Io);
    }
    let size = usize::try_from(stat.st_size).map_err(|_| RecoveryError::Corrupt)?;
    if size > MAX_RECOVERY_RECORD_BYTES {
        return Err(RecoveryError::Corrupt);
    }
    Ok(())
}
