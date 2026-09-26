#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
//! Native host integration for the protected bundled-runtime supervisor.
//!
//! This module exposes no transport material to Tauri commands. It connects
//! the one-time protected profile directly to `AppCore`, monitors only the
//! proven-owned child, and maps every failure to a closed renderer-safe code.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "qualification_ticket.rs"]
pub mod qualification_ticket;

#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::provider_credential_enrollment::{
    CredentialWriterReaperSnapshot, ProtectedWriterReaperRegistry,
};
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
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment,
};

const BUNDLED_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(250);
const WRITER_REAPER_POLL_INTERVAL: Duration = Duration::from_millis(100);

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
    writer_reapers: Arc<ProtectedWriterReaperRegistry>,
    startup_app: Mutex<Option<tauri::AppHandle>>,
    #[cfg(target_os = "linux")]
    active_signed_linux_v3: Arc<Mutex<Option<ActiveSignedLinuxV3Marker>>>,
    #[cfg(target_os = "linux")]
    signed_linux_v3_latch_path: PathBuf,
}

/// Host-only proof that the active V3 session followed a confirmed installed tuple.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveSignedLinuxV3Marker {
    release_tuple: [u8; 32],
    qualification: [u8; 32],
    generation: u64,
    daemon_identity: [u8; 32],
}

#[cfg(target_os = "linux")]
impl ActiveSignedLinuxV3Marker {
    fn from_confirmed(value: &ConfirmedInstalledNativeEnrollment) -> Option<Self> {
        let facts = value.enrollment_transition_facts()?;
        Some(Self {
            release_tuple: facts.release_tuple_digest,
            qualification: facts.qualification_binding_digest,
            generation: facts.supervisor_generation,
            daemon_identity: value.daemon_identity_binding(),
        })
    }

    fn matches(&self, value: &ConfirmedInstalledNativeEnrollment) -> bool {
        Self::from_confirmed(value) == Some(*self)
    }
}

/// Exclusive native-operation lease retained while a credential prompt is open.
///
/// It holds the async operation fence but never a supervisor mutex, so host UI
/// stays responsive while the exact owned daemon is rechecked after the prompt.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct NativeCredentialEnrollmentLease {
    core: Arc<AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    writer_reapers: Arc<ProtectedWriterReaperRegistry>,
    /// Held for its exclusive-fence side effect; never read directly.
    #[cfg_attr(target_os = "macos", expect(dead_code))]
    operation_permit: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg(target_os = "linux")]
pub struct NativeCredentialEnrollmentLease {
    core: Arc<AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    writer_reapers: Arc<ProtectedWriterReaperRegistry>,
    active_signed_linux_v3: Arc<Mutex<Option<ActiveSignedLinuxV3Marker>>>,
    operation_permit: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub struct NativeCredentialEnrollmentCleanup {
    core: Arc<AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    writer_reapers: Arc<ProtectedWriterReaperRegistry>,
}

#[cfg(target_os = "linux")]
impl NativeCredentialEnrollmentCleanup {
    pub(crate) async fn abort(&self) {
        let supervisor = Arc::clone(&self.supervisor);
        let _ = tauri::async_runtime::spawn_blocking(move || {
            let _ = supervisor.lock().map(|mut value| value.stop());
        })
        .await;
        let _ = self
            .core
            .mark_bundled_runtime_degraded(RuntimeFailureCode::ProtectedActivationUnavailable)
            .await;
        let _ = self.writer_reapers.shutdown();
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct NativeCredentialEnrollmentCleanup {
    core: Arc<AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    writer_reapers: Arc<ProtectedWriterReaperRegistry>,
}

#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
pub type CredentialEnrollmentFuture = Pin<
    Box<
        dyn Future<Output = Result<NativeCredentialEnrollmentLease, AppCoreError>> + Send + 'static,
    >,
>;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "bundled_runtime_parts/enrollment.rs"]
mod enrollment;
#[cfg(target_os = "linux")]
#[path = "bundled_runtime_parts/linux_enrollment_round.rs"]
mod linux_enrollment_round;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub use enrollment::test_only_live_enrollment_runtime;

#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl BundledRuntimeController {
    pub(crate) const fn qualification_admission(
        &self,
    ) -> qualification_ticket::ProtectedQualificationAdmission<'_> {
        qualification_ticket::ProtectedQualificationAdmission::from_protected_discovery(self)
    }
}

#[cfg(target_os = "linux")]
impl BundledRuntimeController {
    pub(crate) fn linux_activation_context(
        &self,
    ) -> Option<(
        std::path::PathBuf,
        runne_api::provider_credential_enrollment::linux_activation_policy::LinuxInstallationFacts,
    )> {
        if self.operation_fence.is_stopping() {
            return None;
        }
        self.supervisor.lock().ok()?.linux_activation_context().ok()
    }
}

include!("bundled_runtime_parts/connect.rs");
include!("bundled_runtime_parts/monitor.rs");
#[cfg(target_os = "linux")]
#[path = "bundled_runtime_parts/linux_v3_latch.rs"]
mod linux_v3_latch;
#[path = "bundled_runtime_parts/restart_cleanup.rs"]
mod restart_cleanup;
include!("bundled_runtime_parts/lifecycle.rs");

#[cfg(test)]
mod tests {
    include!("bundled_runtime_parts/tests.rs");
}
