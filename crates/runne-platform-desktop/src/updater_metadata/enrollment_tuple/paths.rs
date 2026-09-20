#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
#[cfg(unix)]
use std::fs::File;
use std::path::{Path, PathBuf};

use super::{MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleError};
#[cfg(unix)]
use super::enrollment_measurement::{self, OpenedNativeEnrollmentFile};
#[path = "paths/admission.rs"]
mod admission;
#[path = "paths/live_identity.rs"]
mod live_identity;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "paths/executor.rs"]
mod executor;
#[cfg(unix)]
include!("paths/fs.rs");

/// Exact native release files derived from the installed package, never caller input.
#[derive(Debug)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-private visibility prevents callers outside native updater composition from supplying paths"
)]
pub(crate) struct NativeEnrollmentArtifactPathsV1 {
    pub(super) desktop: PathBuf,
    writer: PathBuf,
    pub(in crate::updater_metadata) application: PathBuf,
    #[cfg(unix)]
    root: File,
    #[cfg(unix)]
    pub(super) desktop_file: OpenedNativeEnrollmentFile,
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
    #[cfg_attr(not(target_os = "macos"), allow(clippy::missing_const_for_fn))]
    pub(crate) fn resolve_installed() -> Result<Self, NativeEnrollmentTupleError> {
        #[cfg(target_os = "macos")]
        {
            let executable =
                std::env::current_exe().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
            let paths = Self::from_macos_package_executable(&executable, "runne-desktop", true)?;
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
        desktop: &Path,
        writer: &Path,
        daemon: &Path,
        contract: &Path,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let macos = desktop
            .parent()
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        if writer != macos.join("runne")
            || daemon != macos.join("runned")
            || contract
                != macos
                    .parent()
                    .ok_or(NativeEnrollmentTupleError::Rejected)?
                    .join("Resources/contracts/gocode-ui-client-2/bundle.json")
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let paths = Self::from_macos_package_executable(desktop, "runne-desktop", false)?;
        Ok(paths)
    }

    /// Returns the fixed package writer executable path.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn writer_executable_path(&self) -> std::path::PathBuf {
        self.writer.clone()
    }

    #[cfg(unix)]
    pub(crate) fn measure(
        &self,
    ) -> Result<MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleError> {
        let measured = enrollment_measurement::MeasuredNativeEnrollmentArtifactsV1::measure(
            &self.desktop_file,
            &self.writer_file,
            &self.daemon_file,
            &self.contract_file,
        )?;
        self.confirm_current()?;
        Ok(measured)
    }

    /// Non-unix hosts have no rooted bundle to measure and fail closed.
    #[cfg(not(unix))]
    pub(crate) const fn measure(
        &self,
    ) -> Result<MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleError> {
        let _ = self;
        Err(NativeEnrollmentTupleError::Rejected)
    }

    #[cfg(unix)]
    pub(crate) fn confirm_current(&self) -> Result<(), NativeEnrollmentTupleError> {
        self.revalidate_rooted_entries()?;
        self.verify_live_desktop()
    }

    /// Non-unix hosts have no rooted bundle to revalidate and fail closed.
    #[cfg(not(unix))]
    pub(crate) const fn confirm_current(&self) -> Result<(), NativeEnrollmentTupleError> {
        let _ = self;
        Err(NativeEnrollmentTupleError::Rejected)
    }

    #[cfg(unix)]
    pub(super) fn matches_retained(
        &self,
        fresh: &Self,
    ) -> Result<bool, NativeEnrollmentTupleError> {
        self.confirm_current()?;
        fresh.confirm_current()?;
        Ok(same_directory(&self.root, &fresh.root)
            && self.desktop_file.matches_opened(&fresh.desktop_file)?
            && self.writer_file.matches_opened(&fresh.writer_file)?
            && self.daemon_file.matches_opened(&fresh.daemon_file)?
            && self.contract_file.matches_opened(&fresh.contract_file)?)
    }

    /// Non-unix hosts retain no descriptor-rooted identity to match. The
    /// `Result` shape stays for signature parity with the fallible unix twin.
    #[cfg(not(unix))]
    #[cfg_attr(test, allow(dead_code))]
    #[allow(clippy::unnecessary_wraps)]
    pub(super) const fn matches_retained(
        &self,
        fresh: &Self,
    ) -> Result<bool, NativeEnrollmentTupleError> {
        let _ = (self, fresh);
        Ok(false)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn confirm_current_daemon(
        &self,
        expected_digest: [u8; 32],
    ) -> Result<(), NativeEnrollmentTupleError> {
        self.confirm_current()?;
        let measured = self.daemon_file.measure()?;
        (hex::decode(measured).ok().as_deref() == Some(&expected_digest))
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    pub(super) fn from_macos_package_executable(
        executable: &Path,
        expected_name: &str,
        live_desktop: bool,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let macos = executable
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
        if !executable.is_absolute()
            || executable
                .file_name()
                .is_none_or(|name| name != expected_name)
            || macos.file_name().is_none_or(|name| name != "MacOS")
            || contents.file_name().is_none_or(|name| name != "Contents")
            || application
                .file_name()
                .is_none_or(|name| name != "Runne.app")
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let application_metadata = std::fs::symlink_metadata(&application)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !application_metadata.file_type().is_dir()
            || application_metadata.file_type().is_symlink()
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        #[cfg(unix)]
        {
            let application = std::fs::canonicalize(application)
                .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
            let root = open_absolute_directory(&application)?;
            let desktop = macos.join("runne-desktop");
            let desktop_file = open_rooted_file(&root, &["Contents", "MacOS", "runne-desktop"])?;
            let writer_file = open_rooted_file(&root, &["Contents", "MacOS", "runne"])?;
            let daemon_file = open_rooted_file(&root, &["Contents", "MacOS", "runned"])?;
            let contract_file = open_rooted_file(
                &root,
                &[
                    "Contents",
                    "Resources",
                    "contracts",
                    "gocode-ui-client-2",
                    "bundle.json",
                ],
            )?;
            let writer = macos.join("runne");
            Ok(Self {
                desktop,
                writer,
                application,
                root,
                desktop_file: OpenedNativeEnrollmentFile::new(desktop_file)?,
                writer_file: OpenedNativeEnrollmentFile::new(writer_file)?,
                daemon_file: OpenedNativeEnrollmentFile::new(daemon_file)?,
                contract_file: OpenedNativeEnrollmentFile::new(contract_file)?,
                live_desktop,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = live_desktop;
            Err(NativeEnrollmentTupleError::Rejected)
        }
    }

    #[cfg(unix)]
    fn revalidate_rooted_entries(&self) -> Result<(), NativeEnrollmentTupleError> {
        let root = open_absolute_directory(&self.application)?;
        if !same_directory(&self.root, &root) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let entries = [
            (
                &self.desktop_file,
                &["Contents", "MacOS", "runne-desktop"][..],
            ),
            (&self.writer_file, &["Contents", "MacOS", "runne"][..]),
            (&self.daemon_file, &["Contents", "MacOS", "runned"][..]),
            (
                &self.contract_file,
                &[
                    "Contents",
                    "Resources",
                    "contracts",
                    "gocode-ui-client-2",
                    "bundle.json",
                ][..],
            ),
        ];
        entries.into_iter().try_for_each(|(captured, relative)| {
            let current = open_rooted_file(&self.root, relative)?;
            captured
                .matches_file(&current)?
                .then_some(())
                .ok_or(NativeEnrollmentTupleError::Rejected)
        })
    }


}

#[cfg(test)]
#[path = "paths/tests.rs"]
mod tests;
