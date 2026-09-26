impl ReplayHttpState {
    /// Combines immutable daemon authority/generation with the epoch from the
    /// session authenticated for this request. Enrollment can rotate the
    /// epoch without restarting the HTTP router. The replay authority and
    /// local-session authority are separate namespaces, so retain the former
    /// from daemon configuration and validate the session generation only.
    fn binding_for_authenticated(
        &self,
        authenticated: &AuthenticatedRuntimeSession,
    ) -> Result<ReplayHttpBinding, ReplayHttpFailure> {
        if i64::try_from(authenticated.binding.ephemeral().launch_generation()).ok()
            != Some(self.binding.session_generation)
        {
            return Err(replay_authorization_revoked());
        }
        let epoch = i64::try_from(authenticated.binding.ephemeral().authorization_epoch())
            .map_err(|_| replay_authorization_revoked())?;
        ReplayHttpBinding::new(
            self.binding.authority_id,
            self.binding.session_generation,
            epoch,
        )
        .map_err(|_| replay_authorization_revoked())
    }
}
