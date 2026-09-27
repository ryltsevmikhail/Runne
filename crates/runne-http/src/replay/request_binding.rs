impl ReplayHttpState {
    /// Combines the configured replay authority with generation and epoch from
    /// the session authenticated for this request. Protected enrollment can
    /// rotate both session fields without restarting the HTTP router. The
    /// replay and local-session authorities are separate namespaces, so only
    /// the former comes from daemon configuration; session auth and replay
    /// authorization fence stale generations.
    fn binding_for_authenticated(
        &self,
        authenticated: &AuthenticatedRuntimeSession,
    ) -> Result<ReplayHttpBinding, ReplayHttpFailure> {
        let generation = i64::try_from(authenticated.binding.ephemeral().launch_generation())
            .map_err(|_| replay_authorization_revoked())?;
        let epoch = i64::try_from(authenticated.binding.ephemeral().authorization_epoch())
            .map_err(|_| replay_authorization_revoked())?;
        ReplayHttpBinding::new(self.binding.authority_id, generation, epoch)
            .map_err(|_| replay_authorization_revoked())
    }
}
