//! Feature-gated native root-admission authority for protected desktop launches.
use rand::RngCore;
use runne_api::{
    ProtectedActivationKeys, RootAdmissionAuthenticator, RootAdmissionRequest,
    RootAdmissionVerificationContext, RootHandleAdmission, RootHandleTransferOffer,
    VerifiedRootAdmissionClaims,
};
use runne_application::local_session::LocalSessionService;
use runne_application::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionLease,
    RootAdmissionVerifier, RootAdmissionVerifierError,
};
use runne_platform_desktop::VerifiedRootHandle;
use runne_store::ProjectWorkspaceStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
const MAX_PENDING: usize = 64;
const TTL_MILLIS: u64 = 30_000;
const PRINCIPAL: &str = "local-owner";
include!("root_handle_admission/issued.rs");
include!("root_handle_admission/files.rs");
include!("root_handle_admission/editor.rs");
include!("root_handle_admission/diffs.rs");
include!("root_handle_admission/process.rs");
include!("root_handle_admission/verdict.rs");
#[derive(Clone)]
pub(crate) struct RootAdmissionGateway(Option<Arc<RootHandleAdmissionAuthority>>);
impl RootAdmissionGateway {
    pub(crate) fn unavailable() -> Self {
        Self(None)
    }
    pub(crate) fn protected(value: Arc<RootHandleAdmissionAuthority>) -> Self {
        Self(Some(value))
    }
}
#[derive(Clone)]
pub(crate) struct RootHandleAdmissionAuthority {
    state: Arc<Mutex<State>>,
    authenticator: Arc<RootAdmissionAuthenticator>,
    sessions: Arc<Mutex<LocalSessionService>>,
    store: ProjectWorkspaceStore,
    runtime_authority: Arc<str>,
}
include!("root_handle_admission/state.rs");
pub(crate) struct Lease(Arc<RootHandleAdmissionAuthority>);
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.leases = state.leases.saturating_sub(1);
        }
    }
}
impl RootHandleAdmissionAuthority {
    pub(crate) fn new(
        keys: &ProtectedActivationKeys,
        store: ProjectWorkspaceStore,
        runtime_authority: String,
        sessions: Arc<Mutex<LocalSessionService>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(State {
                leases: 0,
                stopped: false,
                pending: HashMap::new(),
                active: HashMap::new(),
            })),
            authenticator: Arc::new(RootAdmissionAuthenticator::from_protected_activation(keys)),
            sessions,
            store,
            runtime_authority: Arc::from(runtime_authority),
        })
    }
    /// Retains the verified descriptor and issues a claim only for a current owned Workspace.
    pub(crate) fn admit(
        &self,
        offer: &RootHandleTransferOffer,
        root: VerifiedRootHandle,
        now: u64,
    ) -> Result<IssuedRootAdmission, RootAdmissionVerifierError> {
        let current = self.context(now)?;
        let transfer = offer.context();
        if transfer.session_id() != &current.session_id()
            || transfer.launch_generation() != current.launch_generation()
            || transfer.expires_at_unix_millis() < now
        {
            return Err(RootAdmissionVerifierError::Rejected);
        }
        let workspace = self
            .store
            .get_workspace(PRINCIPAL, transfer.workspace_id())
            .map_err(|_| RootAdmissionVerifierError::Rejected)?;
        if workspace.version() != transfer.expected_version() {
            return Err(RootAdmissionVerifierError::Rejected);
        }
        let expires_at = now
            .checked_add(TTL_MILLIS)
            .ok_or(RootAdmissionVerifierError::Unavailable)?;
        let baseline = self
            .store
            .with_current_workspace_version(PRINCIPAL, transfer.workspace_id(), |version| {
                if version != transfer.expected_version() {
                    return Err(ProjectWorkspaceRepositoryError::Unavailable);
                }
                WorkspaceBaseline::capture(&root)
                    .map_err(|_| ProjectWorkspaceRepositoryError::Unavailable)
            })
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
        let mut nonce = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let identity = root.filesystem_identity_digest();
        let request = RootAdmissionRequest::new(
            current,
            transfer.workspace_id(),
            transfer.expected_version(),
            identity,
            offer.digest(),
            nonce,
            expires_at,
        )
        .map_err(|_| RootAdmissionVerifierError::Rejected)?;
        let admission = self
            .authenticator
            .issue(request)
            .map_err(|_| RootAdmissionVerifierError::Rejected)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
        expire(&mut state, now);
        if state.stopped || state.pending.len() >= MAX_PENDING || state.pending.contains_key(&nonce)
        {
            return Err(RootAdmissionVerifierError::Unavailable);
        }
        let digest = admission.admission_digest();
        state.pending.insert(
            nonce,
            Pending {
                workspace: transfer.workspace_id(),
                version: transfer.expected_version(),
                identity,
                offer_digest: offer.digest(),
                digest,
                expires_at,
                baseline,
                _handle: root,
            },
        );
        Ok(IssuedRootAdmission::new(admission, digest))
    }
    /// Fences every native admission before session renewal or shutdown.
    pub(crate) fn fence(&self) -> Result<(), RootAdmissionVerifierError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
        if state.leases != 0 {
            return Err(RootAdmissionVerifierError::Unavailable);
        }
        state.pending.clear();
        state.active.clear();
        Ok(())
    }
    pub(crate) fn shutdown(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.stopped = true;
            state.pending.clear();
            state.active.clear();
        }
    }

    fn context(
        &self,
        now: u64,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError> {
        let binding = self
            .sessions
            .lock()
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?
            .current_binding()
            .clone();
        RootAdmissionVerificationContext::new(
            RootAdmissionVerificationContext::authority_digest_for(&self.runtime_authority),
            *binding.ephemeral().session_id(),
            binding.ephemeral().launch_generation(),
            RootAdmissionVerificationContext::principal_digest_for(PRINCIPAL),
            3,
            PINNED_POLICY_VERSION,
            now,
        )
        .map_err(|_| RootAdmissionVerifierError::Unavailable)
    }
}
impl CurrentRootAdmissionContext for RootAdmissionGateway {
    type Lease = GatewayLease;
    fn acquire_root_admission_lease(&self) -> Result<Self::Lease, RootAdmissionVerifierError> {
        let Some(authority) = &self.0 else {
            return Err(RootAdmissionVerifierError::Unavailable);
        };
        let mut state = authority
            .state
            .lock()
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
        if state.stopped {
            return Err(RootAdmissionVerifierError::Unavailable);
        }
        state.leases = state
            .leases
            .checked_add(1)
            .ok_or(RootAdmissionVerifierError::Unavailable)?;
        Ok(GatewayLease(Some(Lease(Arc::clone(authority)))))
    }
}
pub(crate) struct GatewayLease(Option<Lease>);
impl RootAdmissionLease for GatewayLease {
    fn current_root_admission_context(
        &self,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError> {
        self.0
            .as_ref()
            .ok_or(RootAdmissionVerifierError::Unavailable)?
            .0
            .context(now()?)
    }
}
impl RootAdmissionVerifier for RootAdmissionGateway {
    fn verify_root_admission(
        &self,
        admission: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        let Some(authority) = &self.0 else {
            return Err(RootAdmissionVerifierError::Unavailable);
        };
        let claims = authority
            .authenticator
            .verify(admission)
            .map_err(|_| RootAdmissionVerifierError::Rejected)?;
        // Verdicts are recomputed per command; they are never cached or memoized.
        let moment = now()?;
        let current = authority.context(moment)?;
        let mut state = authority
            .state
            .lock()
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
        expire(&mut state, moment);
        let pending = state
            .pending
            .get(&claims.nonce())
            .ok_or(RootAdmissionVerifierError::Rejected)?;
        let matching = !state.stopped
            && claims.context().policy_version() == PINNED_POLICY_VERSION
            && same_context(claims.context(), &current)
            && claims.workspace_id() == pending.workspace
            && claims.expected_version() == pending.version
            && claims.filesystem_identity_digest() == pending.identity
            && claims.offer_digest() == pending.offer_digest
            && claims.admission_digest() == pending.digest
            && claims.expires_at_unix_millis() == pending.expires_at
            && pending.expires_at > moment;
        if matching {
            let baseline = pending.baseline.clone();
            let handle = pending
                ._handle
                .try_clone()
                .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
            state.active.insert(
                claims.workspace_id(),
                ActiveRoot {
                    version: claims.expected_version(),
                    baseline,
                    handle,
                },
            );
        }
        matching
            .then_some(claims)
            .ok_or(RootAdmissionVerifierError::Rejected)
    }
}
