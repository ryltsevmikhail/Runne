use super::{AGGREGATE, AUTHORITY};
use async_trait::async_trait;
use runne_application::{
    ports::{
        ReplayError, ReplayEvent, ReplayOpenResult, ReplaySession, ReplayState, ReplayStorePort,
    },
    replay_service::ReplayDeliveryPrecommitGuard,
};
use runne_domain::{
    id::EventLogLineageId,
    replay::{ReplayCursor, RetentionManifest},
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct FixtureStore(Mutex<(Option<ReplayCursor>, Option<ReplayCursor>)>);

impl FixtureStore {
    pub fn cursors(&self) -> (Option<ReplayCursor>, Option<ReplayCursor>) {
        self.0.lock().unwrap().clone()
    }

    fn session(
        &self,
        principal: &str,
        generation: i64,
        authority: &[u8; 16],
        epoch: i64,
    ) -> ReplaySession {
        ReplaySession {
            session_id: [0x71; 16],
            principal_id: principal.into(),
            session_generation: generation,
            authority_id: *authority,
            authorization_epoch: epoch,
            aggregate_type: 2,
            aggregate_id: AGGREGATE,
            retained_floor: None,
            retention_generation: 0,
            high_water_position: 9,
            next_page_position: None,
            last_delivered_position: None,
            last_acked_position: None,
            state: ReplayState::CatchingUp,
            high_water_ref: vec![0x72],
            catch_up_completion: None,
            live_delivery_id: None,
            created_at: "fixture".into(),
        }
    }
}

#[async_trait]
impl ReplayStorePort for FixtureStore {
    async fn open_session(
        &self,
        principal: &str,
        generation: i64,
        authority: &[u8; 16],
        epoch: i64,
        _: i32,
        _: &[u8; 16],
        cursor: Option<&ReplayCursor>,
        _: &EventLogLineageId,
        _: &[u8; 32],
        guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplayOpenResult, ReplayError> {
        let session = self.session(principal, generation, authority, epoch);
        guard.inspect(&session, &[])?;
        self.0.lock().unwrap().0 = cursor.cloned();
        Ok(ReplayOpenResult::Opened {
            session,
            events: vec![],
        })
    }

    async fn retention_manifest(
        &self,
        _: &EventLogLineageId,
        _: &[u8; 32],
    ) -> Result<RetentionManifest, ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }
    async fn read_page(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: usize,
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }
    async fn acknowledge(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        cursor: &ReplayCursor,
        guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(), ReplayError> {
        guard.inspect_ack(&self.session("local-owner", 7, &AUTHORITY, 0))?;
        self.0.lock().unwrap().1 = Some(cursor.clone());
        Ok(())
    }
    async fn complete_catch_up(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: &[u8; 32],
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Option<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }
    async fn continue_live(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplaySession, ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }
    async fn poll_live(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }
    async fn close_session(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
    ) -> Result<(), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }
}
