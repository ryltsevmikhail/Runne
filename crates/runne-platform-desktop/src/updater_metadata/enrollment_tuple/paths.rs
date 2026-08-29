use std::fs::File;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};

use super::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleError,
    enrollment_measurement::{self, OpenedNativeEnrollmentFile},
};

/// Exact native release files derived from the installed package, never caller input.
#[derive(Debug)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-private visibility prevents callers outside native updater composition from supplying paths"
)]
pub(crate) struct NativeEnrollmentArtifactPathsV1 {
    desktop: PathBuf,
    application: PathBuf,
    #[cfg(unix)]
    root: File,
    #[cfg(unix)]
    desktop_file: OpenedNativeEnrollmentFile,
    #[cfg(unix)]
    writer_file: OpenedNativeEnrollmentFile,
    #[cfg(unix)]
    daemon_file: OpenedNativeEnrollmentFile,
    #[cfg(unix)]
    contract_file: OpenedNativeEnrollmentFile,
    live_desktop: bool,
}

impl NativeEnrollmentArtifactPathsV1 {
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn resolve_installed() -> Result<Self, NativeEnrollmentTupleError> {
        #[cfg(target_os = "macos")]
        {
            let paths = Self::from_macos_desktop_executable(
                std::env::current_exe().map_err(|_| NativeEnrollmentTupleError::Rejected)?,
                true,
            )?;
            paths.verify_live_desktop()?;
            Ok(paths)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeEnrollmentTupleError::Rejected)
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        desktop: PathBuf,
        writer: &Path,
        daemon: &Path,
        contract: &Path,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let macos = desktop.parent().ok_or(NativeEnrollmentTupleError::Rejected)?;
        if writer != macos.join("runne") || daemon != macos.join("runned")
            || contract != macos.parent().ok_or(NativeEnrollmentTupleError::Rejected)?.join("Resources/contracts/gocode-ui-client-2/bundle.json") {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let paths = Self::from_macos_desktop_executable(desktop, false)?;
        Ok(paths)
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn measure(
        &self,
    ) -> Result<MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleError> {
        #[cfg(unix)]
        {
            let measured = enrollment_measurement::MeasuredNativeEnrollmentArtifactsV1::measure(
                &self.desktop_file,
                &self.writer_file,
                &self.daemon_file,
                &self.contract_file,
            )?;
            self.confirm_current()?;
            Ok(measured)
        }
        #[cfg(not(unix))]
        { Err(NativeEnrollmentTupleError::Rejected) }
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn confirm_current(&self) -> Result<(), NativeEnrollmentTupleError> {
        #[cfg(unix)]
        {
            self.revalidate_rooted_entries()?;
            self.verify_live_desktop()
        }
        #[cfg(not(unix))]
        {
            Err(NativeEnrollmentTupleError::Rejected)
        }
    }

    fn from_macos_desktop_executable(
        desktop: PathBuf,
        live_desktop: bool,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let macos = desktop
            .parent()
            .ok_or(NativeEnrollmentTupleError::Rejected)?
            .to_path_buf();
        let contents = macos
            .parent()
            .ok_or(NativeEnrollmentTupleError::Rejected)?
            .to_path_buf();
        let application = contents
            .parent()
            .ok_or(NativeEnrollmentTupleError::Rejected)?
            .to_path_buf();
        if !desktop.is_absolute()
            || desktop.file_name().is_none_or(|name| name != "runne-desktop")
            || macos.file_name().is_none_or(|name| name != "MacOS")
            || contents.file_name().is_none_or(|name| name != "Contents")
            || application.file_name().is_none_or(|name| name != "Runne.app")
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let application_metadata = std::fs::symlink_metadata(&application)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !application_metadata.file_type().is_dir() || application_metadata.file_type().is_symlink() {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let application = std::fs::canonicalize(application)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        #[cfg(unix)]
        {
            let root = open_absolute_directory(&application)?;
            let desktop_file = open_rooted_file(&root, &["Contents", "MacOS", "runne-desktop"])?;
            let writer_file = open_rooted_file(&root, &["Contents", "MacOS", "runne"])?;
            let daemon_file = open_rooted_file(&root, &["Contents", "MacOS", "runned"])?;
            let contract_file = open_rooted_file(&root, &["Contents", "Resources", "contracts", "gocode-ui-client-2", "bundle.json"])?;
            Ok(Self {
                desktop, application, root,
                desktop_file: OpenedNativeEnrollmentFile::new(desktop_file)?,
                writer_file: OpenedNativeEnrollmentFile::new(writer_file)?,
                daemon_file: OpenedNativeEnrollmentFile::new(daemon_file)?,
                contract_file: OpenedNativeEnrollmentFile::new(contract_file)?,
                live_desktop,
            })
        }
        #[cfg(not(unix))]
        { let _ = live_desktop; Err(NativeEnrollmentTupleError::Rejected) }
    }

    #[cfg(unix)]
    fn revalidate_rooted_entries(&self) -> Result<(), NativeEnrollmentTupleError> {
        let root = open_absolute_directory(&self.application)?;
        if !same_directory(&self.root, &root) { return Err(NativeEnrollmentTupleError::Rejected); }
        let entries = [
            (&self.desktop_file, &["Contents", "MacOS", "runne-desktop"][..]),
            (&self.writer_file, &["Contents", "MacOS", "runne"][..]),
            (&self.daemon_file, &["Contents", "MacOS", "runned"][..]),
            (&self.contract_file, &["Contents", "Resources", "contracts", "gocode-ui-client-2", "bundle.json"][..]),
        ];
        entries.into_iter().try_for_each(|(captured, relative)| {
            let current = open_rooted_file(&self.root, relative)?;
            captured.matches_file(&current)?.then_some(()).ok_or(NativeEnrollmentTupleError::Rejected)
        })
    }

    #[cfg(target_os = "macos")]
    fn verify_live_desktop(&self) -> Result<(), NativeEnrollmentTupleError> {
        if !self.live_desktop { return Ok(()); }
        let pid = std::num::NonZeroU32::new(std::process::id()).ok_or(NativeEnrollmentTupleError::Rejected)?;
        runne_macos_process_identity::MacOsProcessExecutableIdentity::observe(pid, &self.desktop)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?
            .matches_file(self.desktop_file.metadata())
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    #[cfg(not(target_os = "macos"))]
    fn verify_live_desktop(&self) -> Result<(), NativeEnrollmentTupleError> {
        (!self.live_desktop).then_some(()).ok_or(NativeEnrollmentTupleError::Rejected)
    }
}

#[cfg(unix)]
fn open_absolute_directory(path: &Path) -> Result<File, NativeEnrollmentTupleError> {
    let mut current = File::from(open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|_| NativeEnrollmentTupleError::Rejected)?);
    for component in path.components() {
        let Component::Normal(name) = component else { if matches!(component, Component::RootDir) { continue; } return Err(NativeEnrollmentTupleError::Rejected); };
        current = File::from(openat(&current, name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|_| NativeEnrollmentTupleError::Rejected)?);
    }
    valid_directory(&current)?.then_some(current).ok_or(NativeEnrollmentTupleError::Rejected)
}

#[cfg(unix)]
fn open_rooted_file(root: &File, components: &[&str]) -> Result<File, NativeEnrollmentTupleError> {
    let (name, parents) = components.split_last().ok_or(NativeEnrollmentTupleError::Rejected)?;
    let root_stat = fstat(root).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !valid_directory_stat(&root_stat) { return Err(NativeEnrollmentTupleError::Rejected); }
    let mut current = root.try_clone().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    for parent in parents {
        current = File::from(openat(&current, *parent, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|_| NativeEnrollmentTupleError::Rejected)?);
        let stat = fstat(&current).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !valid_directory_stat(&stat) || stat.st_dev != root_stat.st_dev || stat.st_uid != root_stat.st_uid { return Err(NativeEnrollmentTupleError::Rejected); }
    }
    let opened = openat(&current, *name, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let opened = File::from(opened);
    let stat = fstat(&opened).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if stat.st_dev != root_stat.st_dev || stat.st_uid != root_stat.st_uid { return Err(NativeEnrollmentTupleError::Rejected); }
    Ok(opened)
}

#[cfg(unix)]
fn valid_directory(file: &File) -> Result<bool, NativeEnrollmentTupleError> {
    let stat = fstat(file).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    Ok(valid_directory_stat(&stat))
}

#[cfg(unix)]
fn valid_directory_stat(stat: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode).is_dir() && stat.st_mode & 0o022 == 0
}

#[cfg(unix)]
fn same_directory(first: &File, second: &File) -> bool {
    let Ok(first) = fstat(first) else { return false }; let Ok(second) = fstat(second) else { return false };
    first.st_dev == second.st_dev && first.st_ino == second.st_ino && first.st_uid == second.st_uid && first.st_mode == second.st_mode && first.st_nlink == second.st_nlink
}

#[cfg(test)]
#[path = "paths/tests.rs"]
mod tests;
