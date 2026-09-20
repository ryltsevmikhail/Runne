//! NM-06 delivery-side trust re-check: replay delivery and provider dispatch
//! consult the single project trust authority for the CURRENT durable
//! revision before any delivery happens.
//!
//! The check deliberately reuses the existing `admit_source` contract
//! (FilesList channel, no path, no observed token): delivering project-scoped
//! material requires the project to be currently trusted/managed — the same
//! predicate as pre-read admission. Fail-closed: workspace/conversation
//! resolution failures, a closed gate (protected composition without a usable
//! authority) and authority errors all deny. Scopes that never carry
//! project-controlled content (task-run state feeds, audit feeds) are not
//! gated by this type; see the T1 phase report for the scope rationale.

use std::sync::Arc;

use runne_application::ports::{
    ConversationRepository, ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError,
};
use runne_application::project_trust::{
    PermissionMode, ProjectTrustProjectId, SourceAdmissionRequest, SourceChannel,
};
use runne_domain::conversation::Conversation;
use runne_domain::id::{ConversationId, WorkspaceId};
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::ProjectWorkspaceStore;
use runne_store::store::StoreTransaction;

/// Builds the replay-side NM-06 delivery gate: active over the single
/// process authority in protected compositions, closed when the protected
/// composition lost its authority, absent in non-protected builds.
pub(crate) fn replay_trust_gate(
    authority: Option<&Arc<ProjectTrustPolicyAuthority>>,
    store: &StoreTransaction,
) -> Option<DeliveryTrustGate> {
    #[cfg(feature = "desktop-protected")]
    {
        Some(match authority {
            Some(authority) => DeliveryTrustGate::open(Arc::clone(authority), store),
            None => DeliveryTrustGate::closed(),
        })
    }
    #[cfg(not(feature = "desktop-protected"))]
    {
        let _ = (authority, store);
        None
    }
}

/// Denial reason is intentionally content-free: callers map it onto their own
/// closed error vocabulary (replay authorization revocation, provider policy
/// denial) and must never echo project details to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustDeliveryDenied;

#[derive(Clone)]
pub(crate) struct DeliveryTrustGate {
    state: GateState,
}

#[derive(Clone)]
enum GateState {
    /// Trust admission enforced against the single process authority.
    Active(GateInner),
    /// Protected composition without a usable authority: fail closed.
    Closed,
    /// Non-protected build: deliveries are not trust-gated. Constructed only
    /// in non-desktop builds (hence the allow under all-features builds).
    #[allow(dead_code)]
    Disabled,
}

#[derive(Clone)]
struct GateInner {
    authority: Arc<ProjectTrustPolicyAuthority>,
    conversations: StoreTransaction,
    workspaces: ProjectWorkspaceStore,
}

impl DeliveryTrustGate {
    /// Active gate over the single process authority.
    pub(crate) fn open(
        authority: Arc<ProjectTrustPolicyAuthority>,
        store: &StoreTransaction,
    ) -> Self {
        Self {
            state: GateState::Active(GateInner {
                authority,
                conversations: store.clone(),
                workspaces: ProjectWorkspaceStore::from_store(store.clone()),
            }),
        }
    }

    /// Protected composition without a usable authority: fail closed.
    pub(crate) fn closed() -> Self {
        Self {
            state: GateState::Closed,
        }
    }

    /// Non-protected build: deliveries are not trust-gated.
    #[cfg_attr(feature = "desktop-protected", allow(dead_code))]
    pub(crate) fn disabled() -> Self {
        Self {
            state: GateState::Disabled,
        }
    }

    /// Active inner, or `None` for the non-protected build. `Err` = closed.
    fn active(&self) -> Result<Option<&GateInner>, TrustDeliveryDenied> {
        match &self.state {
            GateState::Active(inner) => Ok(Some(inner)),
            GateState::Disabled => Ok(None),
            GateState::Closed => Err(TrustDeliveryDenied),
        }
    }

    /// Provider dispatch delivery: the workspace that owns the conversation
    /// being served must currently satisfy the admission predicate.
    pub(crate) fn ensure_workspace_trusted(
        &self,
        principal: &str,
        workspace_id: WorkspaceId,
    ) -> Result<(), TrustDeliveryDenied> {
        let Some(inner) = self.active()? else {
            return Ok(());
        };
        // Governed-project exemption mirrors the replay path: only projects
        // with an explicit trust record are subject to the dispatch-time
        // re-check; never-governed projects keep pre-T1 dispatch behavior
        // until the grant path ships (T1 PASS).
        match inner.workspaces.get_workspace(principal, workspace_id) {
            // R-9 residual: an unregistered runtime workspace has no governed
            // project identity; content stays under content-policy guards.
            Err(ProjectWorkspaceRepositoryError::NotFound) => return Ok(()),
            Err(_) => return Err(TrustDeliveryDenied),
            Ok(_) => {}
        }
        self.ensure_governed_then_current(inner, principal, workspace_id)
    }

    /// Replay delivery: the workspace that owns the replayed conversation
    /// must currently satisfy the admission predicate.
    pub(crate) fn ensure_conversation_trusted(
        &self,
        principal: &str,
        conversation_id: ConversationId,
    ) -> Result<(), TrustDeliveryDenied> {
        let Some(inner) = self.active()? else {
            return Ok(());
        };
        let stream = inner.conversations.load_conversation(conversation_id);
        // A missing aggregate has no captured material to leak: live-only
        // sessions (open before the first message) stay admissible.
        let Ok(stream) = stream else {
            return Ok(());
        };
        if stream.events.is_empty() {
            return Ok(());
        }
        let aggregate = Conversation::replay(&stream.events).map_err(|_| TrustDeliveryDenied)?;
        match inner
            .workspaces
            .get_workspace(principal, aggregate.workspace_id)
        {
            // R-9 residual: an unregistered runtime workspace has no governed
            // project identity; content stays under content-policy guards.
            Err(ProjectWorkspaceRepositoryError::NotFound) => return Ok(()),
            Err(_) => return Err(TrustDeliveryDenied),
            Ok(_) => {}
        }
        self.ensure_governed_then_current(inner, principal, aggregate.workspace_id)
    }

    /// Delivery-time governance gate: only projects with an explicit trust
    /// record (granted/managed/revoked at least once) are subject to the
    /// delivery-time re-check; never-governed projects keep pre-T1 delivery
    /// behavior until the grant path ships (T1 PASS).
    fn ensure_governed_then_current(
        &self,
        inner: &GateInner,
        principal: &str,
        workspace_id: WorkspaceId,
    ) -> Result<(), TrustDeliveryDenied> {
        let workspace = match inner.workspaces.get_workspace(principal, workspace_id) {
            Ok(workspace) => workspace,
            Err(ProjectWorkspaceRepositoryError::NotFound) => return Ok(()),
            Err(_) => return Err(TrustDeliveryDenied),
        };
        let project = ProjectTrustProjectId::from_bytes(*workspace.project_id().as_bytes());
        match inner.authority.has_explicit_record(project) {
            Ok(true) => self.ensure_current(inner, principal, workspace_id),
            Ok(false) => Ok(()),
            Err(_) => Err(TrustDeliveryDenied),
        }
    }

    fn ensure_current(
        &self,
        inner: &GateInner,
        principal: &str,
        workspace_id: WorkspaceId,
    ) -> Result<(), TrustDeliveryDenied> {
        let workspace = match inner.workspaces.get_workspace(principal, workspace_id) {
            Ok(workspace) => workspace,
            // R-9 residual: a workspace that is not registered yet (e.g. the
            // desktop local flow opens the conversation before the runtime
            // workspace row exists) carries no governed project identity;
            // its content stays under the content-policy guards. Any other
            // resolution error fails closed.
            Err(ProjectWorkspaceRepositoryError::NotFound) => return Ok(()),
            Err(_) => return Err(TrustDeliveryDenied),
        };
        let project = ProjectTrustProjectId::from_bytes(*workspace.project_id().as_bytes());
        inner
            .authority
            .admit_source(
                project,
                SourceAdmissionRequest {
                    channel: SourceChannel::FilesList,
                    path: None,
                    // Fresh durable load: no observed token, no client input.
                    observed_token: None,
                    permission_mode: PermissionMode::Ask,
                },
            )
            .map_err(|_| TrustDeliveryDenied)?;
        Ok(())
    }
}
