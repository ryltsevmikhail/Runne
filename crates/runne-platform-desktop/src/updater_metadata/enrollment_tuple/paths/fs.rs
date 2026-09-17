use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use std::path::Component;

impl NativeEnrollmentArtifactPathsV1 {
    #[cfg(target_os = "macos")]
    pub(super) fn daemon_byte_length(&self) -> Result<u64, NativeEnrollmentTupleError> {
        self.confirm_current()?;
        Ok(self.daemon_file.metadata().len())
    }
}

pub(super) fn open_absolute_directory(path: &Path) -> Result<File, NativeEnrollmentTupleError> {
    let mut current = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?,
    );
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(NativeEnrollmentTupleError::Rejected);
        };
        current = File::from(
            openat(
                &current,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?,
        );
    }
    valid_directory(&current)?
        .then_some(current)
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

pub(super) fn open_rooted_file(
    root: &File,
    components: &[&str],
) -> Result<File, NativeEnrollmentTupleError> {
    let (name, parents) = components
        .split_last()
        .ok_or(NativeEnrollmentTupleError::Rejected)?;
    let root_stat = fstat(root).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !valid_directory_stat(&root_stat) {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let mut current = root
        .try_clone()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    for parent in parents {
        current = File::from(
            openat(
                &current,
                *parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?,
        );
        let stat = fstat(&current).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !valid_directory_stat(&stat)
            || stat.st_dev != root_stat.st_dev
            || stat.st_uid != root_stat.st_uid
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
    }
    let opened = File::from(
        openat(
            &current,
            *name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?,
    );
    let stat = fstat(&opened).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if stat.st_dev != root_stat.st_dev || stat.st_uid != root_stat.st_uid {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok(opened)
}

fn valid_directory(file: &File) -> Result<bool, NativeEnrollmentTupleError> {
    Ok(valid_directory_stat(
        &fstat(file).map_err(|_| NativeEnrollmentTupleError::Rejected)?,
    ))
}

fn valid_directory_stat(stat: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode).is_dir() && stat.st_mode & 0o022 == 0
}

pub(super) fn same_directory(first: &File, second: &File) -> bool {
    let (Ok(first), Ok(second)) = (fstat(first), fstat(second)) else {
        return false;
    };
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
        && first.st_nlink == second.st_nlink
}
