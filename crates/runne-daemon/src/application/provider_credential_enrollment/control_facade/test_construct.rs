impl DaemonProviderCredentialEnrollmentControl {
    #[cfg(all(test, unix))]
    fn start_test_protected_session(
        self: &Arc<Self>,
        keys: &runne_api::ProtectedActivationKeys,
        facts: ProtectedEnrollmentSessionFacts,
        rendezvous: super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
    ) -> Result<DaemonProtectedCredentialEnrollmentSession, ProviderCredentialEnrollmentHostError>
    {
        DaemonProtectedCredentialEnrollmentSession::new(
            Arc::clone(self),
            keys,
            facts,
            rendezvous,
            #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
            None,
        )
    }

    #[cfg(all(
        test,
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    ))]
    pub(crate) fn start_test_published_session(
        self: &Arc<Self>,
        keys: &runne_api::ProtectedActivationKeys,
    ) -> Result<
        (DaemonProtectedCredentialEnrollmentSession, [u8; 16]),
        ProviderCredentialEnrollmentHostError,
    > {
        let facts = ProtectedEnrollmentSessionFacts::for_test();
        let session = facts.http_authority_parts().0;
        let enrollment = self.start_test_protected_session(
            keys,
            facts.clone(),
            super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create()?,
        )?;
        self.publish_http_facts(facts)?;
        Ok((enrollment, session))
    }
}
