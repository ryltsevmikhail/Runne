//! Narrow integration-test harness; production cannot construct a root issuer.

use std::sync::{Arc, Mutex};

use runne_api::{LaunchAuthorityError, ProtectedActivationKeys, ProtectedOwnedLaunchV1};
use runne_application::local_session::LocalSessionService;
use runne_store::ProjectWorkspaceStore;

use super::root_handle_admission::RootHandleAdmissionAuthority;

pub(crate) struct RootAdmissionHarness {
    authority: Arc<RootHandleAdmissionAuthority>,
}

impl RootAdmissionHarness {
    pub(crate) fn new(
        keys: &ProtectedActivationKeys,
        store: ProjectWorkspaceStore,
        runtime_authority: String,
        sessions: Arc<Mutex<LocalSessionService>>,
    ) -> Self {
        let authority = RootHandleAdmissionAuthority::new(keys, store, runtime_authority, sessions);
        Self { authority }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch(
        &self,
        channel: &mut crate::protected_activation::ProtectedActivationChannel,
        frame: &[u8],
        keys: &ProtectedActivationKeys,
        owned: &ProtectedOwnedLaunchV1,
        used: &mut std::collections::VecDeque<([u8; 16], [u8; 32], u64)>,
        previous: u64,
        now: u64,
    ) -> Result<Option<u64>, LaunchAuthorityError> {
        let control =
            crate::protected_activation::ProtectedRootControl::new(Arc::clone(&self.authority));
        crate::protected_activation::dispatch_root_handle_control_frame(
            channel,
            frame,
            keys,
            owned,
            used,
            previous,
            now,
            Some(&control),
        )
    }

    pub(crate) fn run_control(
        &self,
        channel: crate::protected_activation::ProtectedActivationChannel,
        keys: ProtectedActivationKeys,
        owned: ProtectedOwnedLaunchV1,
        sessions: Arc<Mutex<LocalSessionService>>,
        clock: Arc<dyn Fn() -> std::time::Duration + Send + Sync>,
    ) -> Result<(), LaunchAuthorityError> {
        let control =
            crate::protected_activation::ProtectedRootControl::new(Arc::clone(&self.authority));
        crate::protected_activation::run_control_loop(
            channel,
            keys,
            owned,
            sessions,
            clock,
            Some(control),
        )
    }

    pub(crate) async fn shutdown(&self) {
        self.authority.shutdown();
    }
}
