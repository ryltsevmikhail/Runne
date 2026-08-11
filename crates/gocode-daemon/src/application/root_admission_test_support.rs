//! Narrow integration-test harness; production cannot construct a root issuer.

use std::sync::{Arc, Mutex};

use gocode_api::{
    BindWorkspaceRootCommand, LaunchAuthorityError, ProjectCommandContext,
    ProjectWorkspaceCommandHostPort, ProtectedActivationKeys, ProtectedOwnedLaunchV1,
    RootHandleAdmission, RootHandleTransferOffer, VerifiedRootAdmissionClaims,
};
use gocode_application::local_session::LocalSessionService;
use gocode_application::ports::RootAdmissionVerifierError;
use gocode_platform_desktop::VerifiedRootHandle;
use gocode_runtime::RuntimeProjectWorkspaceHost;
use gocode_store::ProjectWorkspaceStore;

use super::root_handle_admission::{RootAdmissionGateway, RootHandleAdmissionAuthority};

pub struct RootAdmissionHarness {
    authority: Arc<RootHandleAdmissionAuthority>,
    gateway: RootAdmissionGateway,
    host: RuntimeProjectWorkspaceHost<
        ProjectWorkspaceStore,
        RootAdmissionGateway,
        RootAdmissionGateway,
    >,
}

impl RootAdmissionHarness {
    pub fn new(
        keys: &ProtectedActivationKeys,
        store: ProjectWorkspaceStore,
        runtime_authority: String,
        sessions: Arc<Mutex<LocalSessionService>>,
    ) -> Self {
        let authority =
            RootHandleAdmissionAuthority::new(keys, store.clone(), runtime_authority, sessions);
        let gateway = RootAdmissionGateway::protected(Arc::clone(&authority));
        let host = RuntimeProjectWorkspaceHost::new(store, gateway.clone(), gateway.clone());
        Self {
            authority,
            gateway,
            host,
        }
    }

    pub fn admit(
        &self,
        offer: &RootHandleTransferOffer,
        root: VerifiedRootHandle,
        now: u64,
    ) -> Result<RootHandleAdmission, RootAdmissionVerifierError> {
        self.authority.admit(offer, root, now)
    }

    pub fn verify(
        &self,
        admission: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        gocode_application::ports::RootAdmissionVerifier::verify_root_admission(
            &self.gateway,
            admission,
        )
    }

    pub fn fence(&self) -> Result<(), RootAdmissionVerifierError> {
        self.authority.fence()
    }

    pub fn take_admission(&self) -> Option<RootHandleAdmission> {
        self.authority.take_test_admission()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
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

    pub fn run_control(
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

    pub async fn bind(
        &self,
        context: ProjectCommandContext,
        command: BindWorkspaceRootCommand,
    ) -> Result<gocode_api::WorkspaceCommandAck, gocode_api::ProjectWorkspaceHostError> {
        self.host.bind_workspace_root(context, command).await
    }

    pub async fn shutdown(&self) {
        self.host.shutdown().await;
    }
}
