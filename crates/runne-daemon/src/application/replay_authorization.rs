use super::*;
use runne_domain::id::ConversationId;
use runne_domain::replay::ReplayScope;

/// Aggregate type the replay HTTP transport assigns to conversation streams
/// (`crates/runne-http/src/replay/handlers.rs`).
const CONVERSATION_AGGREGATE_TYPE: u8 = 2;

pub(super) struct DaemonReplayAuthorization {
    replay_authority_id: [u8; 16],
    local_session: Arc<Mutex<LocalSessionService>>,
    /// NM-06: conversation-scope deliveries re-check the current trust
    /// revision before delivery. `None` (non-protected builds) keeps the
    /// historical behavior; a present-but-closed gate denies.
    trust: Option<trust_delivery::DeliveryTrustGate>,
}

impl DaemonReplayAuthorization {
    pub(super) fn new(
        replay_authority_id: [u8; 16],
        local_session: Arc<Mutex<LocalSessionService>>,
        trust: Option<trust_delivery::DeliveryTrustGate>,
    ) -> Self {
        Self {
            replay_authority_id,
            local_session,
            trust,
        }
    }

    /// NM-06 pre-delivery check: a conversation-scope request must satisfy the
    /// CURRENT trust admission before delivery. Session-scope requests carry
    /// no aggregate; their per-delivery enforcement happens through the
    /// authorized delivery guard, which re-runs the SAVED open-request scope
    /// (this same check) inside the store transaction. Resolving the session's
    /// aggregate here would touch the replay store from inside its own locked
    /// transaction — a lock inversion — so session requests fall through: a
    /// session cannot exist unless its open passed this gate, and every
    /// content delivery on it re-runs the open scope check.
    fn ensure_scope_trusted(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<(), ReplayError> {
        let Some(trust) = &self.trust else {
            return Ok(());
        };
        let Some(ReplayScope::Aggregate {
            aggregate_type: CONVERSATION_AGGREGATE_TYPE,
            aggregate_id,
        }) = request.scope
        else {
            return Ok(());
        };
        let conversation_id = ConversationId::from_bytes(aggregate_id);
        trust
            .ensure_conversation_trusted(&request.principal_id, conversation_id)
            .map_err(|_| ReplayError::AuthorizationRevoked)
    }
}

impl ReplayAuthorizationPort for DaemonReplayAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        if request.authority_id != self.replay_authority_id {
            return Err(ReplayError::AuthorizationRevoked);
        }
        self.ensure_scope_trusted(request)?;
        let generation = u64::try_from(request.session_generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let current = self
            .local_session
            .lock()
            .map_err(|_| ReplayError::AuthorizationRevoked)?
            .current_replay_authorization(&request.principal_id, generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            i64::try_from(current.authorization_epoch())
                .map_err(|_| ReplayError::AuthorizationRevoked)?,
            current.sensitivity_ceiling(),
        )
    }

    fn mutate_with_current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
        mutation: &mut dyn FnMut(&ReplayAuthorizationLease) -> Result<usize, ReplayError>,
    ) -> Result<usize, ReplayError> {
        if request.authority_id != self.replay_authority_id {
            return Err(ReplayError::AuthorizationRevoked);
        }
        self.ensure_scope_trusted(request)?;
        let generation = u64::try_from(request.session_generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let local_session = self
            .local_session
            .lock()
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let current = local_session
            .current_replay_authorization(&request.principal_id, generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let lease = ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            i64::try_from(current.authorization_epoch())
                .map_err(|_| ReplayError::AuthorizationRevoked)?,
            current.sensitivity_ceiling(),
        )?;
        mutation(&lease)
    }
}
