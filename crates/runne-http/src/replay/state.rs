/// Shared state for Replay HTTP handlers.
#[derive(Clone)]
pub struct ReplayHttpState {
    pub service: Arc<ReplayService>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    binding: ReplayHttpBinding,
    limits: LimitsConfig,
    active_page_reads: Arc<Mutex<HashSet<[u8; 16]>>>,
    active_drains: Arc<Mutex<HashSet<[u8; 16]>>>,
    quotas: ReplayQuotaManager,
    session_permits: Arc<Mutex<HashMap<[u8; 16], ReplayCountPermit>>>,
    provisional_resume_sessions: Arc<Mutex<HashMap<[u8; 16], V2ResumeLeaseState>>>,
    provisional_resume_bindings: Arc<Mutex<HashMap<[u8; 16], ReplayHttpBinding>>>,
    baseline_resume_v2_enabled: bool,
}
impl ReplayHttpState {
    pub fn new(
        service: ReplayService,
        binding: ReplayHttpBinding,
        limits: LimitsConfig,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Self {
        Self {
            service: Arc::new(service),
            prohibited_content,
            binding,
            limits,
            active_page_reads: Arc::new(Mutex::new(HashSet::new())),
            active_drains: Arc::new(Mutex::new(HashSet::new())),
            quotas: ReplayQuotaManager::default(),
            session_permits: Arc::new(Mutex::new(HashMap::new())),
            provisional_resume_sessions: Arc::new(Mutex::new(HashMap::new())),
            provisional_resume_bindings: Arc::new(Mutex::new(HashMap::new())),
            baseline_resume_v2_enabled: false,
        }
    }
    #[must_use]
    pub fn with_baseline_resume_v2(mut self, enabled: bool) -> Self {
        self.baseline_resume_v2_enabled = enabled;
        self
    }
    fn claim_page_read(&self, session_id: [u8; 16]) -> Option<SessionClaim> {
        SessionClaim::acquire(Arc::clone(&self.active_page_reads), session_id)
    }
    fn claim_live_drain(&self, session_id: [u8; 16]) -> Option<SessionClaim> {
        SessionClaim::acquire(Arc::clone(&self.active_drains), session_id)
    }
    fn retain_session_permit(
        &self,
        session_id: [u8; 16],
        permit: ReplayCountPermit,
    ) -> Result<(), ReplayHttpFailure> {
        let mut permits = self
            .session_permits
            .lock()
            .map_err(|_| replay_backpressure())?;
        if permits.contains_key(&session_id) {
            return Err(replay_invariant_violation());
        }
        permits.insert(session_id, permit);
        Ok(())
    }
    fn take_session_permit(&self, session_id: &[u8; 16]) -> Option<ReplayCountPermit> {
        self.session_permits
            .lock()
            .ok()
            .and_then(|mut permits| permits.remove(session_id))
    }
    fn release_session_permit(&self, session_id: &[u8; 16]) {
        if let Ok(mut sessions) = self.provisional_resume_sessions.lock() {
            sessions.remove(session_id);
        }
        if let Ok(mut bindings) = self.provisional_resume_bindings.lock() {
            bindings.remove(session_id);
        }
        drop(self.take_session_permit(session_id));
    }
    fn release_session_permit_on_terminal_error(&self, session_id: &[u8; 16], error: &ReplayError) {
        if replay_error_terminates_session(error) {
            self.release_session_permit(session_id);
        }
    }
}
