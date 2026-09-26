#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment,
};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use tokio::sync::OwnedMutexGuard;

use super::{CompiledUpdater, UpdateStatusStore};

/// Owns the updater operation fence throughout native confirmation and dispatch.
pub struct NativeInstalledEnrollmentLease {
    updater: OwnedMutexGuard<CompiledUpdater>,
    prepared: Option<PreparedInstalledNativeEnrollment>,
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    test_revalidation: Option<runne_platform_desktop::TestOnlyEnrollmentRevalidation>,
    #[cfg(target_os = "linux")]
    linux_paths: Option<(PathBuf, PathBuf)>,
}

impl NativeInstalledEnrollmentLease {
    pub(crate) fn prepare_confirmation(&self) -> Result<PreparedInstalledNativeEnrollment, ()> {
        self.updater
            .coordinator
            .prepare_installed_native_enrollment()
            .map_err(|_| ())?
            .ok_or(())
    }
    /// Retained for prompt-time revalidation before confirmation.
    #[cfg(not(target_os = "linux"))]
    #[expect(dead_code, reason = "reserved for prompt-time revalidation")]
    pub(crate) fn refresh(&mut self) -> Result<(), ()> {
        let prepared = self.prepared.take().ok_or(())?;
        self.prepared = self
            .updater
            .coordinator
            .refresh_installed_native_enrollment(prepared)
            .map_err(|_| ())?;
        self.prepared.as_ref().ok_or(())?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn refresh_linux(&mut self) -> Result<(), ()> {
        let (desktop_executable, resource_directory) = self.linux_paths.as_ref().ok_or(())?;
        self.prepared = match self.prepared.take() {
            Some(prepared) => self
                .updater
                .coordinator
                .refresh_linux_installed_native_enrollment(
                    prepared,
                    desktop_executable,
                    resource_directory,
                )
                .map_err(|_| ())?,
            None => self
                .updater
                .coordinator
                .prepare_linux_installed_native_enrollment(desktop_executable, resource_directory)
                .map_err(|_| ())?,
        };
        self.prepared.as_ref().ok_or(())?;
        Ok(())
    }

    pub(crate) fn take_prepared(&mut self) -> Result<PreparedInstalledNativeEnrollment, ()> {
        self.prepared.take().ok_or(())
    }

    pub(crate) fn revalidate_confirmed(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<(), ()> {
        #[cfg(target_os = "linux")]
        {
            let (desktop_executable, resource_directory) = self.linux_paths.as_ref().ok_or(())?;
            self.updater
                .coordinator
                .revalidate_linux_confirmed_native_enrollment(
                    confirmed,
                    desktop_executable,
                    resource_directory,
                )
                .map_err(|_| ())?
                .then_some(())
                .ok_or(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            if let Some(revalidation) = self.test_revalidation.as_ref() {
                return revalidation
                    .revalidate(&self.updater.coordinator, confirmed)
                    .map_err(|_| ())?
                    .then_some(())
                    .ok_or(());
            }
            self.updater
                .coordinator
                .revalidate_confirmed_native_enrollment(confirmed)
                .map_err(|_| ())?
                .then_some(())
                .ok_or(())
        }
    }
}

impl UpdateStatusStore {
    /// Startup may skip an unavailable capability, but never a failed verification.
    pub(crate) async fn prepare_startup_native_enrollment(
        &self,
    ) -> Result<Option<NativeInstalledEnrollmentLease>, ()> {
        if self.updater.is_none() {
            return Ok(None);
        }
        self.prepare_installed_native_enrollment().await
    }

    /// Returns retained fixed-layout evidence from the compiled updater only.
    pub(crate) async fn prepare_installed_native_enrollment(
        &self,
    ) -> Result<Option<NativeInstalledEnrollmentLease>, ()> {
        let updater = self.updater.as_ref().ok_or(())?.clone();
        let updater = updater.lock_owned().await;
        let prepared = updater
            .coordinator
            .prepare_installed_native_enrollment()
            .map_err(|_| ())?;
        Ok(prepared.map(|prepared| NativeInstalledEnrollmentLease {
            updater,
            prepared: Some(prepared),
            #[cfg(target_os = "linux")]
            linux_paths: None,
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            test_revalidation: None,
        }))
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn prepare_linux_installed_native_enrollment(
        &self,
        desktop_executable: &std::path::Path,
        resource_directory: &std::path::Path,
    ) -> Result<Option<NativeInstalledEnrollmentLease>, ()> {
        let updater = self.updater.as_ref().ok_or(())?.clone();
        let updater = updater.lock_owned().await;
        let prepared = updater
            .coordinator
            .prepare_linux_installed_native_enrollment(desktop_executable, resource_directory)
            .map_err(|_| ())?;
        Ok(prepared.map(|prepared| NativeInstalledEnrollmentLease {
            updater,
            prepared: Some(prepared),
            linux_paths: Some((
                desktop_executable.to_path_buf(),
                resource_directory.to_path_buf(),
            )),
        }))
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn prepare_startup_linux_native_enrollment(
        &self,
        desktop_executable: &std::path::Path,
        resource_directory: &std::path::Path,
    ) -> Result<Option<NativeInstalledEnrollmentLease>, ()> {
        let Some(updater) = self.updater.clone() else {
            return Ok(None);
        };
        let updater = updater.lock_owned().await;
        let Some(prepared) = updater
            .coordinator
            .prepare_linux_installed_native_enrollment(desktop_executable, resource_directory)
            .map_err(|_| ())?
        else {
            return Ok(None);
        };
        Ok(Some(NativeInstalledEnrollmentLease {
            updater,
            prepared: Some(prepared),
            linux_paths: Some((
                desktop_executable.to_path_buf(),
                resource_directory.to_path_buf(),
            )),
        }))
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub struct TestOnlyEnrollmentUpdater {
    pub(crate) lease: NativeInstalledEnrollmentLease,
    pub(crate) confirmed: ConfirmedInstalledNativeEnrollment,
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub async fn test_only_current_enrollment_updater(
    directory: &std::path::Path,
) -> TestOnlyEnrollmentUpdater {
    test_only_enrollment_updater(
        runne_platform_desktop::test_only_current_enrollment_updater_fixture(directory),
    )
    .await
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub async fn test_only_expired_enrollment_updater(
    directory: &std::path::Path,
) -> TestOnlyEnrollmentUpdater {
    test_only_enrollment_updater(
        runne_platform_desktop::test_only_expired_enrollment_updater_fixture(directory),
    )
    .await
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
async fn test_only_enrollment_updater(
    fixture: runne_platform_desktop::TestOnlyEnrollmentUpdaterFixture,
) -> TestOnlyEnrollmentUpdater {
    let (coordinator, confirmed, revalidation) = fixture.into_parts();
    let updater = std::sync::Arc::new(tokio::sync::Mutex::new(CompiledUpdater {
        endpoint: None,
        rollback_floor: None,
        coordinator,
    }));
    TestOnlyEnrollmentUpdater {
        lease: NativeInstalledEnrollmentLease {
            updater: updater.lock_owned().await,
            prepared: None,
            #[cfg(target_os = "linux")]
            linux_paths: None,
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            test_revalidation: Some(revalidation),
        },
        confirmed,
    }
}
