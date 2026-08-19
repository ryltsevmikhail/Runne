impl LocalSessionService {
    /// Authorizes a request and returns its revocable replay-baseline issuer.
    pub fn authorize_wire_with_replay_issuer(
        &mut self,
        authority: &[u8; 32],
        now: Duration,
    ) -> Result<
        (
            AuthenticatedRuntimeSession,
            AuthenticatedReplayBaselineIssuer,
        ),
        LocalSessionError,
    > {
        self.authorize_wire_with_replay_issuer_for_binding(authority, &self.binding.clone(), now)
    }
    /// Same as [`Self::authorize_wire_with_replay_issuer`] for an explicit binding.
    pub fn authorize_wire_with_replay_issuer_for_binding(
        &mut self,
        authority: &[u8; 32],
        binding: &RuntimeSessionBinding,
        now: Duration,
    ) -> Result<
        (
            AuthenticatedRuntimeSession,
            AuthenticatedReplayBaselineIssuer,
        ),
        LocalSessionError,
    > {
        let authenticated = self.authorize_wire_for_binding(authority, binding, now)?;
        let session = self
            .sessions
            .get(authority)
            .ok_or(LocalSessionError::Unauthorized)?;
        Ok((
            authenticated,
            AuthenticatedReplayBaselineIssuer {
                binding: session.authenticated.binding.clone(),
                authority: session.authority.clone(),
                expires_at_monotonic: session.authenticated.expires_at_monotonic,
                state: Arc::clone(&session.issuer_state),
            },
        ))
    }
}
