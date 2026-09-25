use rustix::fs::{FileType, Mode, OFlags, fstat, openat};
use std::path::{Component, Path};

use super::super::NativeEnrollmentTupleError;

pub(super) fn validate_relative(path: &Path) -> Result<(), NativeEnrollmentTupleError> {
    if path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        Ok(())
    } else {
        Err(NativeEnrollmentTupleError::Rejected)
    }
}

pub fn open_rooted_path(
    root: &std::fs::File,
    relative: &Path,
) -> Result<std::fs::File, NativeEnrollmentTupleError> {
    validate_relative(relative)?;
    let root_stat = fstat(root).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let mut current = root
        .try_clone()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let components = relative.components().collect::<Vec<_>>();
    let (last, parents) = components
        .split_last()
        .ok_or(NativeEnrollmentTupleError::Rejected)?;
    for component in parents {
        let Component::Normal(name) = component else {
            return Err(NativeEnrollmentTupleError::Rejected);
        };
        current = std::fs::File::from(
            openat(
                &current,
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?,
        );
        let stat = fstat(&current).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !valid_directory(&stat)
            || stat.st_dev != root_stat.st_dev
            || stat.st_uid != root_stat.st_uid
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
    }
    let Component::Normal(name) = last else {
        return Err(NativeEnrollmentTupleError::Rejected);
    };
    let file = std::fs::File::from(
        openat(
            &current,
            *name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?,
    );
    let stat = fstat(&file).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if stat.st_dev != root_stat.st_dev || stat.st_uid != root_stat.st_uid {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok(file)
}

fn valid_directory(stat: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode).is_dir() && stat.st_mode & 0o022 == 0
}
