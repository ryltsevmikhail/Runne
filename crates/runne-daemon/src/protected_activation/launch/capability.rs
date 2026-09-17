impl ProtectedDaemonLaunch {
    /// Revalidates the retained sealed release evidence on the authenticated peer.
    pub(crate) fn revalidate_enrollment_capability(
        &self,
        channel: &ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        #[cfg(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        ))]
        if self
            .enrollment_capability
            .as_ref()
            .is_some_and(|capability| {
                !capability.revalidate_for_authenticated_desktop_peer(channel.unix_stream())
            })
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        #[cfg(not(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        )))]
        let _ = (self, channel);
        Ok(())
    }
}
