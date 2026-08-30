#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment,
};
use tokio::sync::OwnedMutexGuard;

use super::{CompiledUpdater, UpdateStatusStore};

/// Owns the updater operation fence throughout native confirmation and dispatch.
pub struct NativeInstalledEnrollmentLease {
    updater: OwnedMutexGuard<CompiledUpdater>,
    prepared: Option<PreparedInstalledNativeEnrollment>,
}

impl NativeInstalledEnrollmentLease {
    /// Retained for prompt-time revalidation before confirmation.
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

    pub(crate) fn take_prepared(&mut self) -> Result<PreparedInstalledNativeEnrollment, ()> {
        self.prepared.take().ok_or(())
    }

    pub(crate) fn revalidate_confirmed(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<(), ()> {
        self.updater
            .coordinator
            .revalidate_confirmed_native_enrollment(confirmed)
            .map_err(|_| ())?
            .then_some(())
            .ok_or(())
    }
}

impl UpdateStatusStore {
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
        }))
    }
}
