//! Feature-gated native root-admission authority for protected desktop launches.
use gocode_api::{
    ProtectedActivationKeys, RootAdmissionAuthenticator, RootAdmissionRequest,
    RootAdmissionVerificationContext, RootHandleAdmission, RootHandleTransferOffer,
    VerifiedRootAdmissionClaims,
};
use gocode_application::local_session::LocalSessionService;
use gocode_application::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionLease,
    RootAdmissionVerifier, RootAdmissionVerifierError,
};
use gocode_platform_desktop::VerifiedRootHandle;
use gocode_store::ProjectWorkspaceStore;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
const MAX_PENDING: usize = 64;
const TTL_MILLIS: u64 = 30_000;
const PRINCIPAL: &str = "local-owner";
include!("root_handle_admission/issued.rs");
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
struct State {
    leases: usize,
    stopped: bool,
    pending: HashMap<[u8; 16], Pending>,
}
struct Pending {
    workspace: gocode_domain::id::WorkspaceId,
    version: u64,
    identity: [u8; 32],
    digest: [u8; 32],
    expires_at: u64,
    _handle: VerifiedRootHandle,
}
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
                digest,
                expires_at,
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
        Ok(())
    }
    pub(crate) fn shutdown(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.stopped = true;
            state.pending.clear();
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
            1,
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
            && same_context(claims.context(), &current)
            && claims.workspace_id() == pending.workspace
            && claims.expected_version() == pending.version
            && claims.filesystem_identity_digest() == pending.identity
            && claims.admission_digest() == pending.digest
            && claims.expires_at_unix_millis() == pending.expires_at
            && pending.expires_at > moment;
        matching
            .then_some(claims)
            .ok_or(RootAdmissionVerifierError::Rejected)
    }
}
fn same_context(
    left: &RootAdmissionVerificationContext,
    right: &RootAdmissionVerificationContext,
) -> bool {
    left.authority_digest() == right.authority_digest()
        && left.session_id() == right.session_id()
        && left.launch_generation() == right.launch_generation()
        && left.principal_digest() == right.principal_digest()
        && left.capability_version() == right.capability_version()
        && left.policy_version() == right.policy_version()
        && left.now_unix_millis() <= right.now_unix_millis()
}
fn expire(state: &mut State, moment: u64) {
    state.pending.retain(|_, item| item.expires_at > moment);
}
fn now() -> Result<u64, RootAdmissionVerifierError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(RootAdmissionVerifierError::Unavailable)
}
