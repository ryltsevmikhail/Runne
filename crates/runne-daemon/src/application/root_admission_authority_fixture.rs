//! Public test-only fixture around the daemon root-admission authority.
//!
//! Production cannot construct a root issuer; this module exists only under
//! `test-support` + `desktop-protected` and never enters the production graph.

use std::sync::{Arc, Mutex};

use runne_api::ProjectWorkspaceHostError;
use runne_api::{
    BindWorkspaceRootCommand, ProjectCommandContext, ProjectWorkspaceCommandHostPort,
    ProtectedActivationKeys, RootAdmissionAuthenticator, RootHandleAdmission,
    RootHandleTransferOffer, VerifiedRootAdmissionClaims, WorkspaceCommandAck,
};
use runne_application::local_session::LocalSessionService;
use runne_application::ports::{RootAdmissionVerifier, RootAdmissionVerifierError};
use runne_platform_desktop::VerifiedRootHandle;
use runne_store::ProjectWorkspaceStore;

use super::root_handle_admission::{RootAdmissionGateway, RootHandleAdmissionAuthority};

/// A daemon-issued admission plus every binding the daemon retained for it.
pub struct IssuedTestAdmission {
    pub admission: RootHandleAdmission,
    pub nonce: [u8; 16],
    pub admission_digest: [u8; 32],
    pub offer_digest: [u8; 32],
    pub expires_at: u64,
    pub filesystem_identity: [u8; 32],
}

/// In-process daemon admission authority wired with the caller's store/sessions.
pub struct RootAdmissionAuthorityFixture {
    authority: Arc<RootHandleAdmissionAuthority>,
    gateway: RootAdmissionGateway,
    unavailable: RootAdmissionGateway,
    authenticator: RootAdmissionAuthenticator,
    sessions: Arc<Mutex<LocalSessionService>>,
    bind_host: Arc<
        runne_runtime::RuntimeProjectWorkspaceHost<
            ProjectWorkspaceStore,
            RootAdmissionGateway,
            RootAdmissionGateway,
        >,
    >,
}

impl RootAdmissionAuthorityFixture {
    pub fn new(
        keys: &ProtectedActivationKeys,
        store: ProjectWorkspaceStore,
        runtime_authority: String,
        sessions: Arc<Mutex<LocalSessionService>>,
    ) -> Self {
        let authority = RootHandleAdmissionAuthority::new(
            keys,
            store.clone(),
            runtime_authority,
            Arc::clone(&sessions),
        );
        let gateway = RootAdmissionGateway::protected(Arc::clone(&authority));
        let bind_host = Arc::new(runne_runtime::RuntimeProjectWorkspaceHost::new(
            store,
            gateway.clone(),
            gateway.clone(),
        ));
        Self {
            authority,
            unavailable: RootAdmissionGateway::unavailable(),
            authenticator: RootAdmissionAuthenticator::from_protected_activation(keys),
            gateway,
            sessions,
            bind_host,
        }
    }

    /// The daemon-pinned policy generation every signed claim must carry.
    pub const fn pinned_policy_version() -> u64 {
        super::root_handle_admission::PINNED_POLICY_VERSION
    }

    /// Issues an admission through the real daemon authority and retains its bindings.
    pub fn issue(
        &self,
        offer: &RootHandleTransferOffer,
        root: VerifiedRootHandle,
        now: u64,
    ) -> Result<IssuedTestAdmission, RootAdmissionVerifierError> {
        let filesystem_identity = root.filesystem_identity_digest();
        let expires_at = offer.context().expires_at_unix_millis();
        let issued = self.authority.admit(offer, root, now)?;
        let (raw, admission_digest) = issued.into_parts();
        let admission = runne_api::test_support::into_untrusted_admission(raw);
        let claims = runne_api::test_support::verify_untrusted(&self.authenticator, &admission);
        Ok(IssuedTestAdmission {
            nonce: claims.nonce(),
            filesystem_identity,
            expires_at,
            admission,
            admission_digest,
            offer_digest: offer.digest(),
        })
    }

    /// Runs the real daemon verdict for one admission; recomputed per command.
    pub fn verify(
        &self,
        admission: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        self.gateway.verify_root_admission(admission)
    }

    /// Same verdict through a gateway whose authority is absent.
    pub fn verify_unavailable_authority(
        &self,
        admission: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        self.unavailable.verify_root_admission(admission)
    }

    /// Fences every retained admission, as session renewal or shutdown would.
    pub fn fence(&self) -> Result<(), RootAdmissionVerifierError> {
        self.authority.fence()
    }

    /// Retained verdict state: (pending admissions, durable active roots).
    pub fn retained_effect(&self) -> (usize, usize) {
        self.authority.retained_effect()
    }

    /// Replaces the daemon session service, as a session rotation would.
    pub fn replace_session(&self, sessions: LocalSessionService) {
        *self.sessions.lock().expect("sessions") = sessions;
    }

    /// Drives the daemon-side bind entry point behind the HTTP root-bindings POST.
    pub async fn bind_workspace_root(
        &self,
        command: ProjectCommandContext,
        request: BindWorkspaceRootCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        self.bind_host.bind_workspace_root(command, request).await
    }
}
