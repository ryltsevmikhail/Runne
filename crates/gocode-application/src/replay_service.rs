//! ReplayService — event replay coordination with durable session cursors.
//!
//! Provides:
//! - [`ReplayStorePort`] — async port for replay subscription persistence
//! - [`ReplayService`] — coordinator that delegates to the store
//! - [`ReplaySession`], [`ReplayEvent`], [`ReplayState`] — domain data types
//! - [`ReplayError`] — closed, typed replay errors

use async_trait::async_trait;
use std::sync::Arc;

// ── Domain types ────────────────────────────────────────────────────────────

/// Replay subscription state machine states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayState {
    /// Initial catch-up phase: events are being read from the event log.
    CatchingUp,
    /// All pre-existing events have been delivered and acknowledged.
    CatchUpComplete,
    /// The activator is transitioning to live delivery.
    ActivatingLive,
    /// Live delivery: poller is active for new events.
    Live,
    /// Session is terminated.
    Closed,
}

impl ReplayState {
    /// Parse from the SQL TEXT representation.
    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "catching_up" => Some(Self::CatchingUp),
            "catch_up_complete" => Some(Self::CatchUpComplete),
            "activating_live" => Some(Self::ActivatingLive),
            "live" => Some(Self::Live),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }

    /// Convert to SQL TEXT representation.
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::CatchingUp => "catching_up",
            Self::CatchUpComplete => "catch_up_complete",
            Self::ActivatingLive => "activating_live",
            Self::Live => "live",
            Self::Closed => "closed",
        }
    }
}

/// Session data stored in `_replay_subscriptions` table.
#[derive(Clone, Debug)]
pub struct ReplaySession {
    /// Unique session identifier (16 bytes).
    pub session_id: [u8; 16],
    /// Authenticated principal that owns this session.
    pub principal_id: String,
    /// Monotonic generation counter for lease fencing.
    pub session_generation: i64,
    /// The runtime authority that created this session.
    pub authority_id: [u8; 16],
    /// Authorization epoch for revocation fencing.
    pub authorization_epoch: i64,
    /// Aggregate type discriminant (1 = TaskRun, 2 = Conversation).
    pub aggregate_type: i32,
    /// Aggregate identity (16-byte UUID).
    pub aggregate_id: [u8; 16],
    /// Retained event floor (None before pruning).
    pub retained_floor: Option<i64>,
    /// Retention generation (always 0 in Phase 4).
    pub retention_generation: i64,
    /// Global position of the high-water mark at session open.
    pub high_water_position: i64,
    /// Next page cursor for catch-up reads.
    pub next_page_position: Option<i64>,
    /// Last delivered position to the client.
    pub last_delivered_position: Option<i64>,
    /// Last acknowledged position by the client.
    pub last_acked_position: Option<i64>,
    /// Current state machine state.
    pub state: ReplayState,
    /// HMAC-protected high-water reference (77 bytes).
    pub high_water_ref: Vec<u8>,
    /// Catch-up completion proof (opaque to clients).
    pub catch_up_completion: Option<Vec<u8>>,
    /// Live delivery identifier (opaque to clients).
    pub live_delivery_id: Option<Vec<u8>>,
    /// Session creation timestamp (ISO-8601).
    pub created_at: String,
}

/// Event row from the `events` table.
#[derive(Clone, Debug)]
pub struct ReplayEvent {
    /// Global commit position of the event.
    pub global_position: i64,
    /// Event identity (16-byte UUID).
    pub event_id: [u8; 16],
    /// Aggregate type discriminant.
    pub aggregate_type: i32,
    /// Aggregate identity (16-byte UUID).
    pub aggregate_id: [u8; 16],
    /// Serialized event payload.
    pub payload: Vec<u8>,
    /// Event timestamp (Unix microseconds).
    pub timestamp: i64,
    /// Event type string for dispatch.
    pub event_type: String,
}

// ── Port ─────────────────────────────────────────────────────────────────────

/// ReplayStore port — thread-safe async trait for replay subscription persistence.
///
/// All methods require the full authorization binding
/// (`principal_id`, `generation`, `authority_id`, `epoch`) to prevent
/// session hijacking and to enforce lease fencing.
#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait ReplayStorePort: Send + Sync {
    /// Atomically open a replay session.
    ///
    /// Captures the high-water mark, inserts a session row, and returns
    /// the first page of events — all in one transaction.
    async fn open_session(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        server_secret: &[u8; 32],
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError>;

    /// Read the next page of events after the last delivered position.
    async fn read_page(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        limit: usize,
    ) -> Result<Vec<ReplayEvent>, ReplayError>;

    /// Mark catch-up as complete with a proof.
    ///
    /// The session must be in `CatchingUp` state. The proof is stored
    /// in the session row and returned to the client as an opaque blob.
    async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        catch_up_completion_proof: &[u8],
    ) -> Result<ReplaySession, ReplayError>;

    /// CAS-activate live delivery.
    ///
    /// Transitions `CatchUpComplete → ActivatingLive → Live` atomically.
    /// Only one activator succeeds; others fail with `InvalidState`.
    async fn continue_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<ReplaySession, ReplayError>;

    /// Poll for new events after the high-water mark (live delivery).
    async fn poll_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<Vec<ReplayEvent>, ReplayError>;

    /// Close the session.
    ///
    /// Session must be in `CatchUpComplete` or `Live` state.
    async fn close_session(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError>;
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Closed set of replay errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReplayError {
    /// The session was not found in the store.
    #[error("session not found")]
    SessionNotFound,

    /// Authorization binding mismatch (principal, generation, authority, epoch).
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Invalid state transition (e.g., attempting to close from `CatchingUp`).
    #[error("invalid state transition from {0}")]
    InvalidState(String),

    /// The session generation is stale (lease fencing).
    #[error("stale generation")]
    StaleGeneration,

    /// A persistent storage failure.
    #[error("storage error: {0}")]
    Storage(String),

    /// A data integrity violation.
    #[error("integrity error: {0}")]
    Integrity(String),
}

// ── Service ──────────────────────────────────────────────────────────────────

/// ReplayService coordinates replay sessions.
///
/// Delegates all persistence to a [`ReplayStorePort`] implementation.
/// Holds the in-memory `server_secret` for HMAC-protected `HighWaterRef` construction.
pub struct ReplayService {
    store: Arc<dyn ReplayStorePort>,
    server_secret: [u8; 32],
}

impl ReplayService {
    /// Create a new `ReplayService`.
    pub fn new(store: Arc<dyn ReplayStorePort>, server_secret: [u8; 32]) -> Self {
        Self {
            store,
            server_secret,
        }
    }

    /// Open a replay session and return the first page of events.
    pub async fn open_session(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        self.store
            .open_session(
                principal_id,
                session_generation,
                authority_id,
                authorization_epoch,
                aggregate_type,
                aggregate_id,
                &self.server_secret,
            )
            .await
    }

    /// Read the next page of events for a catch-up session.
    pub async fn read_page(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        limit: usize,
    ) -> Result<Vec<ReplayEvent>, ReplayError> {
        self.store
            .read_page(
                session_id,
                principal_id,
                generation,
                authority_id,
                epoch,
                limit,
            )
            .await
    }

    /// Complete catch-up with a proof.
    pub async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        proof: &[u8],
    ) -> Result<ReplaySession, ReplayError> {
        self.store
            .complete_catch_up(
                session_id,
                principal_id,
                generation,
                authority_id,
                epoch,
                proof,
            )
            .await
    }

    /// CAS-activate live delivery.
    pub async fn continue_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<ReplaySession, ReplayError> {
        self.store
            .continue_live(session_id, principal_id, generation, authority_id, epoch)
            .await
    }

    /// Poll for new live events.
    pub async fn poll_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<Vec<ReplayEvent>, ReplayError> {
        self.store
            .poll_live(session_id, principal_id, generation, authority_id, epoch)
            .await
    }

    /// Close the session.
    pub async fn close_session(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError> {
        self.store
            .close_session(session_id, principal_id, generation, authority_id, epoch)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_state_roundtrip() {
        let states = vec![
            ReplayState::CatchingUp,
            ReplayState::CatchUpComplete,
            ReplayState::ActivatingLive,
            ReplayState::Live,
            ReplayState::Closed,
        ];

        for state in &states {
            let db = state.as_db();
            let parsed = ReplayState::from_db(db).unwrap();
            assert_eq!(parsed, *state);
        }
    }

    #[test]
    fn test_replay_state_from_db_unknown() {
        assert!(ReplayState::from_db("bogus").is_none());
    }

    #[test]
    fn test_replay_service_new() {
        use std::sync::Arc;

        struct DummyStore;
        #[async_trait]
        impl ReplayStorePort for DummyStore {
            async fn open_session(
                &self,
                _p: &str,
                _g: i64,
                _a: &[u8; 16],
                _e: i64,
                _t: i32,
                _id: &[u8; 16],
                _s: &[u8; 32],
            ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
                Err(ReplayError::Storage("dummy".into()))
            }
            async fn read_page(
                &self,
                _s: &[u8; 16],
                _p: &str,
                _g: i64,
                _a: &[u8; 16],
                _e: i64,
                _l: usize,
            ) -> Result<Vec<ReplayEvent>, ReplayError> {
                Err(ReplayError::Storage("dummy".into()))
            }
            async fn complete_catch_up(
                &self,
                _s: &[u8; 16],
                _p: &str,
                _g: i64,
                _a: &[u8; 16],
                _e: i64,
                _proof: &[u8],
            ) -> Result<ReplaySession, ReplayError> {
                Err(ReplayError::Storage("dummy".into()))
            }
            async fn continue_live(
                &self,
                _s: &[u8; 16],
                _p: &str,
                _g: i64,
                _a: &[u8; 16],
                _e: i64,
            ) -> Result<ReplaySession, ReplayError> {
                Err(ReplayError::Storage("dummy".into()))
            }
            async fn poll_live(
                &self,
                _s: &[u8; 16],
                _p: &str,
                _g: i64,
                _a: &[u8; 16],
                _e: i64,
            ) -> Result<Vec<ReplayEvent>, ReplayError> {
                Err(ReplayError::Storage("dummy".into()))
            }
            async fn close_session(
                &self,
                _s: &[u8; 16],
                _p: &str,
                _g: i64,
                _a: &[u8; 16],
                _e: i64,
            ) -> Result<(), ReplayError> {
                Err(ReplayError::Storage("dummy".into()))
            }
        }

        let secret = [0xAAu8; 32];
        let svc = ReplayService::new(Arc::new(DummyStore), secret);
        // Just check construction succeeds
        assert!(!svc.server_secret.is_empty());
    }
}
