use super::*;

impl LocalSessionService {
    /// Releases only the session proven by this authority and revokes its replay issuers.
    /// Capacity, bootstrap replay protection and other live sessions are unchanged.
    pub fn close_session(
        &mut self,
        authority: &[u8; 32],
        now: Duration,
    ) -> Result<(), LocalSessionError> {
        self.authorize_wire(authority, now)?;
        let session = self
            .sessions
            .remove(authority)
            .ok_or(LocalSessionError::Unauthorized)?;
        session.issuer_state.revoked.store(true, Ordering::Release);
        Ok(())
    }
}
