#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
//! Native host integration for the protected bundled-runtime supervisor.
//!
//! This module exposes no transport material to Tauri commands. It connects
//! the one-time protected profile directly to `AppCore`, monitors only the
//! proven-owned child, and maps every failure to a closed renderer-safe code.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{
    NativeRootAdmission, NativeRootAdmissionLifecycle, OwnedRuntimeLifecycle, RootAdmissionFuture,
    RootAdmissionReapFuture, RuntimeConnectionFuture,
};
use runne_api::ProviderActivationReadinessV1;
use runne_app_core::{
    AppCore, AppCoreError, BundledRuntimeActivationLease, RuntimeAvailability, RuntimeFailureCode,
    RuntimeMode,
};
use runne_platform_desktop::{
    BundledRuntimeLifecycleState, BundledRuntimeStopDisposition, DevelopmentBundledRuntimeLauncher,
    PROTECTED_BUNDLED_SESSION_RENEW_AFTER, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeSupervisor, discover_bundled_runtime,
};
use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment,
};

const BUNDLED_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Opaque compile-time gate for the native loopback fixture only.
///
/// It is unavailable from a release desktop build, has no renderer surface,
/// and cannot convey a production provider enrollment.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug)]
pub struct NativeOpenAiActivationTestGate(());

#[cfg(feature = "test-support")]
impl NativeOpenAiActivationTestGate {
    #[must_use]
    pub const fn loopback_fixture() -> Self {
        Self(())
    }
}

/// Closed host-side result of the explicit-quit shutdown policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledShutdownOutcome {
    Graceful,
    Forced,
    Incomplete,
}

struct RuntimeOperationFence {
    stopping: AtomicBool,
    operation: Arc<tokio::sync::Mutex<()>>,
}

impl RuntimeOperationFence {
    fn new() -> Self {
        Self {
            stopping: AtomicBool::new(false),
            operation: Arc::new(tokio::sync::Mutex::const_new(())),
        }
    }

    async fn enter(&self) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        if self.is_stopping() {
            return None;
        }
        let guard = Arc::clone(&self.operation).lock_owned().await;
        if self.is_stopping() {
            return None;
        }
        Some(guard)
    }

    fn begin_shutdown(&self) -> bool {
        !self.stopping.swap(true, Ordering::AcqRel)
    }

    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    fn wait_for_idle(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.operation.blocking_lock()
    }
}

#[derive(Debug)]
struct ProtectedSessionRenewalSchedule {
    renew_after: Duration,
    deadline: Option<Instant>,
}

impl ProtectedSessionRenewalSchedule {
    const fn new(renew_after: Duration) -> Self {
        Self {
            renew_after,
            deadline: None,
        }
    }

    fn arm(&mut self, now: Instant) {
        self.deadline = now.checked_add(self.renew_after);
    }

    const fn clear(&mut self) {
        self.deadline = None;
    }

    fn is_due(&self, now: Instant) -> bool {
        self.deadline.is_none_or(|deadline| now >= deadline)
    }
}

/// Connects `AppCore` to one concrete protected bundled-runtime supervisor.
pub struct BundledRuntimeController {
    core: Arc<AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    operation_fence: Arc<RuntimeOperationFence>,
    renewal_schedule: Mutex<ProtectedSessionRenewalSchedule>,
    shutdown_outcome: Mutex<Option<BundledShutdownOutcome>>,
}

/// Exclusive native-operation lease retained while a credential prompt is open.
///
/// It holds the async operation fence but never a supervisor mutex, so host UI
/// stays responsive while the exact owned daemon is rechecked after the prompt.
pub struct NativeCredentialEnrollmentLease {
    core: Arc<AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    /// Held for its exclusive-fence side effect; never read directly.
    #[cfg_attr(target_os = "macos", expect(dead_code))]
    operation_permit: tokio::sync::OwnedMutexGuard<()>,
}

pub type CredentialEnrollmentFuture = Pin<
    Box<
        dyn Future<Output = Result<NativeCredentialEnrollmentLease, AppCoreError>> + Send + 'static,
    >,
>;

impl NativeCredentialEnrollmentLease {
    /// Opaque handle for one native daemon dispatch on the leased supervisor.
    pub(crate) fn supervisor_handle(
        &self,
    ) -> Arc<std::sync::Mutex<ProtectedBundledRuntimeSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    pub(crate) async fn confirm(
        &self,
        prepared: PreparedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .confirm_installed_native_enrollment(prepared)
                .map_err(|_| AppCoreError::RuntimeUnavailable)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?
    }

    /// Fences the V2 `AppCore` client, transitions the exact daemon, then
    /// installs only the authenticated rotated V3 profile.
    pub(crate) async fn transition_and_install(
        &self,
        confirmed: ConfirmedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, AppCoreError> {
        let activation = self.core.begin_bundled_runtime_restart().await?;
        let transition = self
            .install_transitioned_profile(activation, confirmed)
            .await;
        match transition {
            Ok(confirmed) => Ok(confirmed),
            Err(_) => self.fail_transition().await,
        }
    }

    pub(crate) fn rotated_intent_session_binding(&self) -> Result<[u8; 32], AppCoreError> {
        self.supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .current_credential_enrollment_intent_binding()
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    pub(crate) fn abort_enrollment(&self) {
        let _ = self.supervisor.lock().map(|mut value| value.stop());
        let _ = tauri::async_runtime::block_on(
            self.core
                .mark_bundled_runtime_degraded(RuntimeFailureCode::ProtectedActivationUnavailable),
        );
    }

    async fn install_transitioned_profile(
        &self,
        activation: BundledRuntimeActivationLease,
        confirmed: ConfirmedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        let confirmed = tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .begin_credential_enrollment_transition(&confirmed)
                .map_err(|_| AppCoreError::RuntimeUnavailable)?;
            Ok::<_, AppCoreError>(confirmed)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)??;
        let profile = self
            .supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .take_runtime_profile()
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        let Ok(client) = profile.connect(BUNDLED_CLIENT_CONNECT_TIMEOUT).await else {
            return Err(AppCoreError::RuntimeUnavailable);
        };
        let checked = client.clone();
        let supervisor = Arc::clone(&self.supervisor);
        if tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .record_client_ready(&checked)
                .map_err(|_| AppCoreError::RuntimeUnavailable)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?
        .is_err()
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        if self
            .core
            .install_bundled_runtime_client(activation, client)
            .await
            .is_err()
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        Ok(confirmed)
    }

    async fn fail_transition<T>(&self) -> Result<T, AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        let _ = tauri::async_runtime::spawn_blocking(move || {
            let _ = supervisor.lock().map(|mut value| value.stop());
        })
        .await;
        let _ = self
            .core
            .mark_bundled_runtime_degraded(RuntimeFailureCode::ProtectedActivationUnavailable)
            .await;
        Err(AppCoreError::RuntimeUnavailable)
    }
}

impl crate::RuntimeLifecycleManager {
    pub(crate) async fn acquire_credential_enrollment_lease(
        &self,
    ) -> Result<NativeCredentialEnrollmentLease, AppCoreError> {
        if self.is_shutting_down() || self.runtime_mode != RuntimeMode::Bundled {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.root_admission
            .as_ref()
            .ok_or(AppCoreError::RuntimeUnavailable)?
            .acquire_credential_enrollment_lease()
            .await
    }
}

include!("bundled_runtime_parts/connect.rs");
include!("bundled_runtime_parts/monitor.rs");
include!("bundled_runtime_parts/lifecycle.rs");

#[cfg(test)]
mod tests {
    include!("bundled_runtime_parts/tests.rs");
}
