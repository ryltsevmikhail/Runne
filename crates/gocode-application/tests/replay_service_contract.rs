//! Contract tests for ReplayService → ReplayStorePort delegation.
//!
//! Verifies that ReplayService correctly forwards calls to the store
//! and does not add extra logic beyond delegation.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use gocode_application::ports::{
    ReplayError, ReplayEvent, ReplaySession, ReplayState, ReplayStorePort,
};
use gocode_application::replay_service::ReplayService;

// ── Mock store ───────────────────────────────────────────────────────────

/// Tracks which methods were called and with what parameters.
#[derive(Default)]
struct CallLog {
    open_session_count: usize,
    read_page_count: usize,
    complete_catch_up_count: usize,
    continue_live_count: usize,
    poll_live_count: usize,
    close_session_count: usize,
    last_principal: Option<String>,
    last_limit: Option<usize>,
}

#[derive(Clone)]
struct MockStore {
    log: Arc<Mutex<CallLog>>,
}

impl MockStore {
    fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(CallLog::default())),
        }
    }

    fn log(&self) -> std::sync::MutexGuard<'_, CallLog> {
        self.log.lock().unwrap()
    }

    fn make_session() -> ReplaySession {
        ReplaySession {
            session_id: [0x01u8; 16],
            principal_id: "test".to_string(),
            session_generation: 1,
            authority_id: [0xAA; 16],
            authorization_epoch: 0,
            aggregate_type: 1,
            aggregate_id: [0xBB; 16],
            retained_floor: None,
            retention_generation: 0,
            high_water_position: 0,
            next_page_position: None,
            last_delivered_position: None,
            last_acked_position: None,
            state: ReplayState::CatchingUp,
            high_water_ref: vec![0u8; 77],
            catch_up_completion: None,
            live_delivery_id: None,
            created_at: "2026-01-01T00:00:00".to_string(),
        }
    }
}

#[async_trait]
impl ReplayStorePort for MockStore {
    async fn open_session(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        _server_secret: &[u8; 32],
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        let mut log = self.log.lock().unwrap();
        log.open_session_count += 1;
        log.last_principal = Some(principal_id.to_string());
        drop(log);

        // Verify forwarded parameters
        assert_eq!(principal_id, "test-user");
        assert_eq!(session_generation, 42);
        assert_eq!(*authority_id, [0xAA; 16]);
        assert_eq!(authorization_epoch, 7);
        assert_eq!(aggregate_type, 1);
        assert_eq!(*aggregate_id, [0xBB; 16]);

        Ok((Self::make_session(), vec![]))
    }

    async fn read_page(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        _authority_id: &[u8; 16],
        _epoch: i64,
        limit: usize,
    ) -> Result<Vec<ReplayEvent>, ReplayError> {
        let mut log = self.log.lock().unwrap();
        log.read_page_count += 1;
        log.last_limit = Some(limit);
        drop(log);

        assert_eq!(*session_id, [0x01u8; 16]);
        assert_eq!(principal_id, "test-user");
        assert_eq!(generation, 42);
        assert_eq!(limit, 50);

        Ok(vec![])
    }

    async fn complete_catch_up(
        &self,
        _session_id: &[u8; 16],
        principal_id: &str,
        _generation: i64,
        _authority_id: &[u8; 16],
        _epoch: i64,
        catch_up_completion_proof: &[u8],
    ) -> Result<ReplaySession, ReplayError> {
        let mut log = self.log.lock().unwrap();
        log.complete_catch_up_count += 1;
        log.last_principal = Some(principal_id.to_string());
        drop(log);

        assert_eq!(catch_up_completion_proof, b"done");
        let mut session = Self::make_session();
        session.state = ReplayState::CatchUpComplete;
        Ok(session)
    }

    async fn continue_live(
        &self,
        _session_id: &[u8; 16],
        principal_id: &str,
        _generation: i64,
        _authority_id: &[u8; 16],
        _epoch: i64,
    ) -> Result<ReplaySession, ReplayError> {
        let mut log = self.log.lock().unwrap();
        log.continue_live_count += 1;
        log.last_principal = Some(principal_id.to_string());
        drop(log);

        let mut session = Self::make_session();
        session.state = ReplayState::Live;
        session.live_delivery_id = Some(vec![0x42u8; 16]);
        Ok(session)
    }

    async fn poll_live(
        &self,
        _session_id: &[u8; 16],
        principal_id: &str,
        _generation: i64,
        _authority_id: &[u8; 16],
        _epoch: i64,
    ) -> Result<Vec<ReplayEvent>, ReplayError> {
        let mut log = self.log.lock().unwrap();
        log.poll_live_count += 1;
        log.last_principal = Some(principal_id.to_string());
        drop(log);

        Ok(vec![])
    }

    async fn close_session(
        &self,
        _session_id: &[u8; 16],
        principal_id: &str,
        _generation: i64,
        _authority_id: &[u8; 16],
        _epoch: i64,
    ) -> Result<(), ReplayError> {
        let mut log = self.log.lock().unwrap();
        log.close_session_count += 1;
        log.last_principal = Some(principal_id.to_string());
        drop(log);

        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

const AUTH: [u8; 16] = [0xAA; 16];
const AGG: [u8; 16] = [0xBB; 16];
const SID: [u8; 16] = [0x01; 16];
const SECRET: [u8; 32] = [0xCC; 32];

#[tokio::test]
async fn service_forward_contract() {
    let mock = MockStore::new();
    let svc = ReplayService::new(Arc::new(mock.clone()), SECRET);

    // open_session
    let (session, events) = svc
        .open_session("test-user", 42, &AUTH, 7, 1, &AGG)
        .await
        .unwrap();
    assert_eq!(session.state, ReplayState::CatchingUp);
    assert!(events.is_empty());
    assert_eq!(mock.log().open_session_count, 1);

    // read_page
    let page = svc
        .read_page(&SID, "test-user", 42, &AUTH, 7, 50)
        .await
        .unwrap();
    assert!(page.is_empty());
    assert_eq!(mock.log().read_page_count, 1);
    assert_eq!(mock.log().last_limit, Some(50));

    // complete_catch_up
    let session = svc
        .complete_catch_up(&SID, "test-user", 42, &AUTH, 7, b"done")
        .await
        .unwrap();
    assert_eq!(session.state, ReplayState::CatchUpComplete);
    assert_eq!(mock.log().complete_catch_up_count, 1);

    // continue_live
    let session = svc
        .continue_live(&SID, "test-user", 42, &AUTH, 7)
        .await
        .unwrap();
    assert_eq!(session.state, ReplayState::Live);
    assert!(session.live_delivery_id.is_some());
    assert_eq!(mock.log().continue_live_count, 1);

    // poll_live
    let live = svc
        .poll_live(&SID, "test-user", 42, &AUTH, 7)
        .await
        .unwrap();
    assert!(live.is_empty());
    assert_eq!(mock.log().poll_live_count, 1);

    // close_session
    svc.close_session(&SID, "test-user", 42, &AUTH, 7)
        .await
        .unwrap();
    assert_eq!(mock.log().close_session_count, 1);

    // All methods were called exactly once
    assert_eq!(mock.log().last_principal.as_deref(), Some("test-user"));
}
