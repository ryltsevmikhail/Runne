//! NM-06 delivery-side trust re-check: replay delivery and provider dispatch
//! consult the conversation's durable context marker plus the single project
//! trust authority for the CURRENT durable revision before any delivery.
//!
//! Explicit text-only conversations deliver from their marker alone.
//! Workspace-scoped (or unmarked) conversations deliver only through the
//! existing `admit_source` contract (FilesList channel, no path, no observed
//! token) after their workspace resolves and an explicit trust record exists.
//! Fail-closed: a missing marker never widens provenance; workspace/
//! conversation resolution failures, a closed gate (protected composition
//! without a usable authority) and authority errors all deny. Scopes that
//! never carry project-controlled content (task-run state feeds, audit feeds)
//! are not gated by this type; see the T1 phase report for the scope
//! rationale.

use std::sync::Arc;

use runne_application::ports::{
    EventStoreError, ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError,
};
use runne_application::project_trust::{
    PermissionMode, ProjectTrustEffectLease, ProjectTrustProjectId, SourceAdmissionRequest,
    SourceChannel,
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
    /// delivery-context contract of its durable marker.
    ///
    /// Provenance contract (T1 policy revision 2): the replay proof is NOT a
    /// text-only proof — replaying as a canonical text-only Conversation says
    /// nothing about which context will be delivered. Delivery is allowed
    /// only from (a) an EXPLICIT durable text-only context marker recorded in
    /// the creation transaction, or (b) a workspace-scoped conversation whose
    /// workspace resolves and whose project carries an explicit, currently
    /// admitted trust record. A missing marker is unknown provenance and
    /// follows the stricter (b) path; the former absence-based allows
    /// (unregistered workspace, never-governed project) are removed.
    /// Read/decode failures and corrupted streams deny (fail-closed). A
    /// retention gap is decided here, never handed to baseline recovery:
    /// delivery proceeds only on an explicit durable TextOnly marker. A
    /// workspace-scoped or unmarked gap denies even for a currently Trusted
    /// project — a gap need not be a lost sequence 1 (the header can
    /// disagree for other reasons), but either way the
    /// conversation→workspace binding is unproven, and the aggregate
    /// snapshot used by recovery is not authenticated trust evidence.
    pub(crate) fn ensure_conversation_trusted(
        &self,
        principal: &str,
        conversation_id: ConversationId,
    ) -> Result<(), TrustDeliveryDenied> {
        let Some(inner) = self.active()? else {
            return Ok(());
        };
        let stream = match inner
            .conversations
            .diagnose_conversation_stream(conversation_id)
        {
            // Confirmed absence: live-only sessions (open before the first
            // message) carry no captured material.
            Err(EventStoreError::NotFound) => return Ok(()),
            // A gap may have lost the sequence-1 event that binds this
            // conversation to its workspace, or disagree with the header
            // for another reason; either way the binding is unproven. Do
            // not infer trust from the unauthenticated aggregate snapshot
            // used by baseline recovery. An explicit durable TextOnly
            // marker is independent of that event and carries no
            // project-controlled content.
            Ok(runne_store::store::ConversationStreamHealth::RetentionGap { .. }) => {
                return if inner
                    .conversations
                    .conversation_context_scope(conversation_id)
                    .is_ok_and(|scope| {
                        scope
                            == Some(runne_domain::conversation::ConversationContextScope::TextOnly)
                    }) {
                    Ok(())
                } else {
                    Err(TrustDeliveryDenied)
                };
            }
            // Corrupt or unreadable streams and other read failures block
            // delivery: they are never classified as "nothing to deliver".
            Ok(runne_store::store::ConversationStreamHealth::Intact(stream)) => stream,
            Ok(runne_store::store::ConversationStreamHealth::Corrupt) | Err(_) => {
                return Err(TrustDeliveryDenied);
            }
        };
        if stream.events.is_empty() {
            // Nothing to deliver regardless of scope.
            return Ok(());
        }
        let scope = inner
            .conversations
            .conversation_context_scope(conversation_id)
            .map_err(|_| TrustDeliveryDenied)?;
        if scope == Some(runne_domain::conversation::ConversationContextScope::TextOnly) {
            // Explicit durable text-only context recorded at creation.
            return Ok(());
        }
        // Workspace-scoped (or unmarked/unknown) conversation: provenance
        // must resolve to a registered project identity with an explicit,
        // current trust record.
        let aggregate = Conversation::replay(&stream.events).map_err(|_| TrustDeliveryDenied)?;
        let workspace = match inner
            .workspaces
            .get_workspace(principal, aggregate.workspace_id)
        {
            Ok(workspace) => workspace,
            // Unknown ownership never becomes deliverable.
            Err(ProjectWorkspaceRepositoryError::NotFound) => return Err(TrustDeliveryDenied),
            Err(_) => return Err(TrustDeliveryDenied),
        };
        let project = ProjectTrustProjectId::from_bytes(*workspace.project_id().as_bytes());
        match inner.authority.has_explicit_record(project) {
            // Governed project: re-check the CURRENT trust admission.
            Ok(true) => self.ensure_current(inner, project),
            // A lost trust record does not upgrade the project: without an
            // explicit record there is no trust to deliver against.
            Ok(false) => Err(TrustDeliveryDenied),
            Err(_) => Err(TrustDeliveryDenied),
        }
    }

    /// Holds the current governed-project revision across the durable
    /// provider-effect start transition. The lease is released before network
    /// dispatch; text-only conversations retain their explicit bypass.
    pub(crate) fn acquire_provider_effect_lease(
        &self,
        principal: &str,
        conversation_id: ConversationId,
    ) -> Result<Option<Box<dyn ProjectTrustEffectLease>>, TrustDeliveryDenied> {
        let Some(inner) = self.active()? else {
            return Ok(None);
        };
        let stream = match inner
            .conversations
            .diagnose_conversation_stream(conversation_id)
        {
            Ok(runne_store::store::ConversationStreamHealth::Intact(stream)) => stream,
            _ => return Err(TrustDeliveryDenied),
        };
        if stream.events.is_empty() {
            return Err(TrustDeliveryDenied);
        }
        let scope = inner
            .conversations
            .conversation_context_scope(conversation_id)
            .map_err(|_| TrustDeliveryDenied)?;
        if scope == Some(runne_domain::conversation::ConversationContextScope::TextOnly) {
            return Ok(None);
        }
        let aggregate = Conversation::replay(&stream.events).map_err(|_| TrustDeliveryDenied)?;
        let workspace = inner
            .workspaces
            .get_workspace(principal, aggregate.workspace_id)
            .map_err(|_| TrustDeliveryDenied)?;
        let project = ProjectTrustProjectId::from_bytes(*workspace.project_id().as_bytes());
        // FilesList + Ask is the inherited delivery-gate convention: a
        // managed FilesList deny intentionally blocks provider delivery
        // too (over-deny); a dedicated channel is only a new policy revision.
        inner
            .authority
            .acquire_effect_lease(
                project,
                SourceAdmissionRequest {
                    channel: SourceChannel::FilesList,
                    path: None,
                    observed_token: None,
                    permission_mode: PermissionMode::Ask,
                },
            )
            .map(Some)
            .map_err(|_| TrustDeliveryDenied)
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
