#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected prompt composition retains this lease until control dispatch"
    )
)]
#![cfg_attr(test, allow(dead_code))]

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
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the protected prompt composition requests this only after acquiring its lease"
        )
    )]
    #[cfg_attr(test, allow(dead_code))]
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
