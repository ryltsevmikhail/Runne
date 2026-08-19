use super::*;

pub(super) struct DaemonReplayAuthorization {
    replay_authority_id: [u8; 16],
    local_session: Arc<Mutex<LocalSessionService>>,
}

impl DaemonReplayAuthorization {
    pub(super) fn new(
        replay_authority_id: [u8; 16],
        local_session: Arc<Mutex<LocalSessionService>>,
    ) -> Self {
        Self {
            replay_authority_id,
            local_session,
        }
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
