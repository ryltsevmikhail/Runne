const MAX_V2_RESUME_DELIVERY_LEASE: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Copy, Eq, PartialEq)]
enum V2ResumeLeaseState {
    Pending,
    Delivered,
    Reaping,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum V2ResumeDeliveryClaim {
    Ordinary,
    Delivered,
    Reaping,
}

fn claim_v2_resume_delivery_state(
    sessions: &mut HashMap<[u8; 16], V2ResumeLeaseState>,
    session_id: &[u8; 16],
) -> V2ResumeDeliveryClaim {
    match sessions.get_mut(session_id) {
        None => V2ResumeDeliveryClaim::Ordinary,
        Some(state @ V2ResumeLeaseState::Pending) => {
            *state = V2ResumeLeaseState::Delivered;
            V2ResumeDeliveryClaim::Delivered
        }
        Some(V2ResumeLeaseState::Delivered | V2ResumeLeaseState::Reaping) => {
            V2ResumeDeliveryClaim::Reaping
        }
    }
}

fn claim_v2_resume_reaping_state(
    sessions: &mut HashMap<[u8; 16], V2ResumeLeaseState>,
    session_id: &[u8; 16],
    expected: V2ResumeLeaseState,
) -> bool {
    match sessions.get_mut(session_id) {
        Some(state) if *state == expected => {
            *state = V2ResumeLeaseState::Reaping;
            true
        }
        Some(_) | None => false,
    }
}

fn resume_delivery_deadline(expires_at_unix_ms: u64) -> tokio::time::Instant {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .unwrap_or(expires_at_unix_ms);
    let remaining = std::time::Duration::from_millis(expires_at_unix_ms.saturating_sub(now).max(1))
        .min(MAX_V2_RESUME_DELIVERY_LEASE);
    tokio::time::Instant::now() + remaining
}

impl ReplayHttpState {
    fn retain_v2_session_permit(
        &self,
        session_id: [u8; 16],
        principal_id: String,
        permit: ReplayCountPermit,
        delivery_deadline: tokio::time::Instant,
        binding: ReplayHttpBinding,
    ) -> Result<(), ReplayHttpFailure> {
        let inserted = match self.provisional_resume_sessions.lock() {
            Ok(mut sessions) => match sessions.entry(session_id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(V2ResumeLeaseState::Pending);
                    true
                }
                std::collections::hash_map::Entry::Occupied(_) => false,
            },
            Err(_) => {
                self.spawn_forced_v2_resume_reap(session_id, principal_id, binding);
                return Err(replay_backpressure());
            }
        };
        if !inserted {
            return Err(replay_invariant_violation());
        }
        let binding_inserted = self
            .provisional_resume_bindings
            .lock()
            .map(|mut bindings| match bindings.entry(session_id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(binding);
                    true
                }
                std::collections::hash_map::Entry::Occupied(_) => false,
            })
            .unwrap_or(false);
        if !binding_inserted {
            if let Ok(mut sessions) = self.provisional_resume_sessions.lock() {
                sessions.remove(&session_id);
            }
            self.spawn_forced_v2_resume_reap(session_id, principal_id, binding);
            return Err(replay_invariant_violation());
        }
        if let Err(error) = self.retain_session_permit(session_id, permit) {
            self.begin_v2_resume_reaping(session_id, principal_id);
            return Err(error);
        }
        if delivery_deadline <= tokio::time::Instant::now() {
            self.begin_v2_resume_reaping(session_id, principal_id);
            return Err(replay_authorization_revoked());
        }
        let state = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(delivery_deadline).await;
            state.begin_v2_resume_reaping(session_id, principal_id);
        });
        Ok(())
    }

    fn claim_v2_resume_delivery(&self, session_id: &[u8; 16]) -> V2ResumeDeliveryClaim {
        let Ok(mut sessions) = self.provisional_resume_sessions.lock() else {
            return V2ResumeDeliveryClaim::Reaping;
        };
        claim_v2_resume_delivery_state(&mut sessions, session_id)
    }

    fn finish_v2_resume_delivery(&self, session_id: &[u8; 16]) {
        if let Ok(mut sessions) = self.provisional_resume_sessions.lock()
            && sessions.get(session_id) == Some(&V2ResumeLeaseState::Delivered)
        {
            sessions.remove(session_id);
            if let Ok(mut bindings) = self.provisional_resume_bindings.lock() {
                bindings.remove(session_id);
            }
        }
    }

    fn provisional_resume_binding(&self, session_id: &[u8; 16]) -> Option<ReplayHttpBinding> {
        self.provisional_resume_bindings
            .lock()
            .ok()?
            .get(session_id)
            .copied()
    }

    fn begin_v2_resume_reaping(&self, session_id: [u8; 16], principal_id: String) {
        let should_spawn = match self.provisional_resume_sessions.lock() {
            Ok(mut sessions) => claim_v2_resume_reaping_state(
                &mut sessions,
                &session_id,
                V2ResumeLeaseState::Pending,
            ),
            Err(_) => {
                if let Some(binding) = self.provisional_resume_binding(&session_id) {
                    self.spawn_forced_v2_resume_reap(session_id, principal_id, binding);
                }
                return;
            }
        };
        if let Some(binding) = self.provisional_resume_binding(&session_id) {
            self.spawn_v2_resume_reaper(should_spawn, session_id, principal_id, binding);
        }
    }

    fn fail_v2_resume_delivery(&self, session_id: [u8; 16], principal_id: String) {
        let should_spawn = match self.provisional_resume_sessions.lock() {
            Ok(mut sessions) => claim_v2_resume_reaping_state(
                &mut sessions,
                &session_id,
                V2ResumeLeaseState::Delivered,
            ),
            Err(_) => {
                if let Some(binding) = self.provisional_resume_binding(&session_id) {
                    self.spawn_forced_v2_resume_reap(session_id, principal_id, binding);
                }
                return;
            }
        };
        if let Some(binding) = self.provisional_resume_binding(&session_id) {
            self.spawn_v2_resume_reaper(should_spawn, session_id, principal_id, binding);
        }
    }

    fn spawn_v2_resume_reaper(
        &self,
        should_spawn: bool,
        session_id: [u8; 16],
        principal_id: String,
        binding: ReplayHttpBinding,
    ) {
        if should_spawn {
            let state = self.clone();
            tokio::spawn(async move {
                state
                    .reap_v2_resume(session_id, principal_id, true, binding)
                    .await;
            });
        }
    }

    fn spawn_forced_v2_resume_reap(
        &self,
        session_id: [u8; 16],
        principal_id: String,
        binding: ReplayHttpBinding,
    ) {
        let state = self.clone();
        tokio::spawn(async move {
            state
                .reap_v2_resume(session_id, principal_id, false, binding)
                .await;
        });
    }

    async fn reap_v2_resume(
        &self,
        session_id: [u8; 16],
        principal_id: String,
        require_reaping_state: bool,
        binding: ReplayHttpBinding,
    ) {
        loop {
            let still_reaping = self
                .provisional_resume_sessions
                .lock()
                .map(|sessions| sessions.get(&session_id) == Some(&V2ResumeLeaseState::Reaping))
                .unwrap_or(false);
            if require_reaping_state && !still_reaping {
                return;
            }
            match self
                .service
                .close_session(
                    &session_id,
                    &principal_id,
                    binding.session_generation,
                    &binding.authority_id,
                    binding.authorization_epoch,
                )
                .await
            {
                Ok(()) | Err(ReplayError::SessionNotFound) => {
                    self.release_session_permit(&session_id);
                    return;
                }
                Err(ReplayError::AuthorizationRevoked) => {
                    // This lease is permanently stale after a generation or
                    // epoch rotation. The session is fenced by replay auth;
                    // retain no local quota while durable expiry reclaims it.
                    self.release_session_permit(&session_id);
                    return;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            }
        }
    }
}
