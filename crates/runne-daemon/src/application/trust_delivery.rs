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
    ConversationRepository, EventStoreError, ProjectWorkspaceRepository,
    ProjectWorkspaceRepositoryError,
};
use runne_application::project_trust::{
    PermissionMode, ProjectTrustProjectId, SourceAdmissionRequest, SourceChannel,
};
use runne_domain::conversation::Conversation;
use runne_domain::id::ConversationId;
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
#[cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
pub(crate) struct DeliveryTrustGate {
    state: GateState,
}

#[derive(Clone)]
#[cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
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
    #[cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
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
    #[cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
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

    /// Replay delivery: the committed conversation must currently satisfy the
    /// admission predicate of its registered project.
    ///
    /// Explicit text-only delivery contract (DP1): a stream is deliverable
    /// only when it replays as a canonical text-only Conversation — every
    /// committed event is a user/assistant text message. Project-controlled
    /// content channels (instructions/skills/hooks/local MCP) are
    /// unavailable-by-absence (inventory §A), so a successfully replayed
    /// aggregate proves no project-controlled content is being delivered.
    /// Read/decode failures and non-replayable streams deny (fail-closed).
    pub(crate) fn ensure_conversation_trusted(
        &self,
        principal: &str,
        conversation_id: ConversationId,
    ) -> Result<(), TrustDeliveryDenied> {
        let Some(inner) = self.active()? else {
            return Ok(());
        };
        let stream = match inner.conversations.load_conversation(conversation_id) {
            // Confirmed absence: live-only sessions (open before the first
            // message) carry no captured material.
            Err(EventStoreError::NotFound) => return Ok(()),
            // Read failures block delivery: a corrupt or unreadable stream is
            // never classified as "nothing to deliver".
            Err(_) => return Err(TrustDeliveryDenied),
            Ok(stream) => stream,
        };
        if stream.events.is_empty() {
            return Ok(());
        }
        // Replay success IS the text-only proof (DP1): every committed event
        // is a user/assistant text message and project-controlled channels
        // are unavailable by absence (inventory §A). A stream that fails to
        // replay proves nothing, so it never delivers (fail-closed) — decode
        // errors must not be classified as deliverable text-only context.
        let aggregate = Conversation::replay(&stream.events).map_err(|_| TrustDeliveryDenied)?;
        let workspace = match inner
            .workspaces
            .get_workspace(principal, aggregate.workspace_id)
        {
            // Replay-proven text-only stream, unregistered workspace: no
            // governed project identity exists (R-9 residual).
            Err(ProjectWorkspaceRepositoryError::NotFound) => return Ok(()),
            Ok(workspace) => workspace,
            Err(_) => return Err(TrustDeliveryDenied),
        };
        let project = ProjectTrustProjectId::from_bytes(*workspace.project_id().as_bytes());
        match inner.authority.has_explicit_record(project) {
            // Governed project: re-check the CURRENT trust admission.
            Ok(true) => self.ensure_current(inner, project),
            // Never-governed project: pre-T1 delivery behavior under the
            // explicit text-only contract (residual R-11).
            Ok(false) => Ok(()),
            Err(_) => Err(TrustDeliveryDenied),
        }
    }

    /// Current-revision admission for an already-identified project. The
    /// caller resolves the project from the workspace row it just loaded, so
    /// no second workspace lookup happens here (no TOCTOU re-read window).
    fn ensure_current(
        &self,
        inner: &GateInner,
        project: ProjectTrustProjectId,
    ) -> Result<(), TrustDeliveryDenied> {
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
            .map(|_| ())
            .map_err(|_| TrustDeliveryDenied)
    }
}
