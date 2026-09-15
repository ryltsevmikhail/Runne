impl DaemonProviderCredentialEnrollmentControl {
    pub(crate) fn new(
        store: Arc<SqliteProviderCredentialLifecycleStore>,
        readback: Arc<dyn ProviderCredentialReadback>,
        measurements: CredentialEnrollmentMeasurementAuthority,
        enrollment_store_authority: CredentialEnrollmentStoreAuthority,
        runtime_authority: [u8; 16],
        database_generation: u64,
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))] credential_service: Option<
            Arc<crate::protected_activation::CredentialServiceRuntimeGateway>,
        >,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if runtime_authority == [0; 16] || database_generation == 0 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let handles = ProviderCredentialOperationHandleIssuer::new(http::generate_handle_key()?);
        let rendezvous = PendingBrokerRendezvousRegistry::new(handles.duplicate());
        #[cfg(any(
            all(test, unix),
            all(
                feature = "desktop-protected",
                target_os = "macos",
                target_arch = "aarch64"
            )
        ))]
        let (http_authority_issuer, http_authority_verifier) =
            ProviderCredentialRequestAuthorityPair::new().split();
        Ok(Self {
            store,
            readback,
            measurements,
            enrollment_store_authority,
            handles,
            rendezvous,
            #[cfg(any(
                all(test, unix),
                all(
                    feature = "desktop-protected",
                    target_os = "macos",
                    target_arch = "aarch64"
                )
            ))]
            verification: OnceLock::new(),
            #[cfg(any(
                all(test, unix),
                all(target_os = "macos", feature = "desktop-protected")
            ))]
            local_readback: OnceLock::new(),
            #[cfg(any(
                all(test, unix),
                all(
                    feature = "desktop-protected",
                    target_os = "macos",
                    target_arch = "aarch64"
                )
            ))]
            http_authority_issuer,
            #[cfg(any(
                all(test, unix),
                all(
                    feature = "desktop-protected",
                    target_os = "macos",
                    target_arch = "aarch64"
                )
            ))]
            http_authority_verifier,
            #[cfg(any(
                all(test, unix),
                all(
                    feature = "desktop-protected",
                    target_os = "macos",
                    target_arch = "aarch64"
                )
            ))]
            http_facts: super::http_admission_resolver::live_credential_http_facts(),
            #[cfg(all(
                feature = "desktop-protected",
                target_os = "macos",
                target_arch = "aarch64"
            ))]
            runtime_authority,
            #[cfg(all(
                feature = "desktop-protected",
                target_os = "macos",
                target_arch = "aarch64"
            ))]
            database_generation,
            #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
            credential_service,
        })
    }

    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    pub(crate) fn install_verification(
        &self,
        verification: Arc<dyn super::ProviderCredentialVerificationHost>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.verification
            .set(verification)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }

    #[cfg(any(
        all(test, unix),
        all(target_os = "macos", feature = "desktop-protected")
    ))]
    pub(crate) fn install_local_readback(
        &self,
        readback: Arc<dyn runne_secure_store::ProviderCredentialVerificationReadback>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        install_local_readback_once(&self.local_readback, readback)
    }

    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    pub(crate) fn measurement_authority(&self) -> CredentialEnrollmentMeasurementAuthority {
        self.measurements.clone()
    }

    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    pub(crate) fn operation_handle_issuer(&self) -> ProviderCredentialOperationHandleIssuer {
        self.handles.duplicate()
    }

    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    pub(crate) fn verify_admitted(
        &self,
        verifier: ProviderCredentialRequestAuthorityVerifier,
        authority: ProviderCredentialBaseRequestAuthority,
        proof: ProviderCredentialIntentConsumptionProof,
        context: ProviderCredentialCommandContext,
        command: VerifyProviderCredential,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        ProviderCredentialAdmission::new(verifier, self.measurements.clone())
            .require_verify_command(&authority, &proof, &command, &context)?;
        self.verification
            .get()
            .ok_or(ProviderCredentialEnrollmentHostError::Unsupported)?
            .verify(authority, proof, context, command)
    }

    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    pub(crate) fn install_credential_service_session(
        &self,
        session: crate::protected_activation::CredentialServiceRuntimeSession,
    ) -> Result<
        Arc<crate::protected_activation::CredentialServiceRuntimeGateway>,
        ProviderCredentialEnrollmentHostError,
    > {
        let gateway = self
            .credential_service
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::Unsupported)?;
        gateway.install(session)?;
        self.install_local_readback(Arc::clone(gateway)
            as Arc<dyn runne_secure_store::ProviderCredentialVerificationReadback>)?;
        super::CredentialEnrollmentRecoveryGateway::new_with_local(
            self.store.as_ref(),
            gateway.as_ref(),
            gateway.as_ref(),
        )
        .reconcile_online(chrono::Utc::now().timestamp())?;
        Ok(Arc::clone(gateway))
    }

    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    #[allow(clippy::too_many_arguments)]
    fn begin_admitted(
        &self,
        verifier: ProviderCredentialRequestAuthorityVerifier,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        context: &ProviderCredentialCommandContext,
        command: &BeginProviderCredentialEnrollment,
        now_high_water: i64,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        ProviderCredentialEnrollmentBegin::new(
            ProviderCredentialAdmission::with_legacy_import_authority(
                verifier,
                self.measurements.clone(),
                self.enrollment_store_authority.clone(),
            ),
            self.handles.duplicate(),
            self.store.as_ref(),
            self.readback.as_ref(),
            self.rendezvous.clone(),
        )
        .admit(authority, proof, context, command, now_high_water)
    }

    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    pub(crate) fn start_protected_session(
        self: &Arc<Self>,
        keys: &runne_api::ProtectedActivationKeys,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        rendezvous: super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
        installed_facts: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    ) -> Result<DaemonProtectedCredentialEnrollmentSession, ProviderCredentialEnrollmentHostError>
    {
        let facts = ProtectedEnrollmentSessionFacts::from_owned(
            owned,
            self.runtime_authority,
            self.database_generation,
        )?;
        let session = DaemonProtectedCredentialEnrollmentSession::new(
            Arc::clone(self),
            keys,
            facts.clone(),
            rendezvous,
            Some(installed_facts),
        )?;
        self.publish_http_facts(facts)?;
        Ok(session)
    }

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

    #[cfg(all(test, unix))]
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
