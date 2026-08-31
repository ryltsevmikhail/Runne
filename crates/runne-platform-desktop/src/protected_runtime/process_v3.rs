// V3 state transitions stay separate from V1/V2 compatibility state. A V3
// enrollment binding never projects to an older protocol version.
#[cfg(test)]
struct VerifiedEnrollmentRenewalV3 {
    bootstrap_ticket: Zeroizing<[u8; 32]>,
    owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
}

#[cfg(test)]
impl VerifiedEnrollmentRenewalV3 {
    const fn enrollment_binding(&self) -> &runne_api::ProtectedCredentialEnrollmentLaunchBindingV1 {
        self.owned.enrollment_binding()
    }

    fn bootstrap_ticket(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.bootstrap_ticket)
    }
}

impl ProtectedProcessActivation {
    #[cfg(test)]
    const fn enrollment_binding(
        &self,
    ) -> Option<&runne_api::ProtectedCredentialEnrollmentLaunchBindingV1> {
        match self {
            Self::V3 { owned, .. } => Some(owned.enrollment_binding()),
            Self::V1 { .. } | Self::V2 { .. } => None,
            #[cfg(feature = "test-support")]
            Self::Test { .. } => None,
        }
    }

    #[cfg(test)]
    const fn v3_ready(&self) -> Option<&runne_api::ProtectedCredentialEnrollmentReadyV3> {
        match self {
            Self::V3 { ready, .. } => Some(ready),
            Self::V1 { .. } | Self::V2 { .. } => None,
            #[cfg(feature = "test-support")]
            Self::Test { .. } => None,
        }
    }

    fn matches_v3_runtime_client(&self, client: &AuthenticatedRuntimeClient) -> Option<bool> {
        let Self::V3 { ready, owned, .. } = self else {
            return None;
        };
        let session = client.session_info();
        Some(
            session.profile_id == owned.profile().profile_id()
                && session.schema_hash == hex::encode(owned.profile().profile_hash())
                && session.authority_id == hex::encode(owned.stable().authority_id())
                && session.principal_id == owned.stable().principal_id()
                && session.event_log_lineage_id
                    == uuid::Uuid::from_bytes(*owned.stable().lineage_id()).to_string()
                && session.daemon_instance_id
                    == uuid::Uuid::from_bytes(*owned.daemon_instance_id()).to_string()
                && session.launch_generation == owned.launch_generation()
                && session.session_id == hex::encode(owned.session_id())
                && session.capability_digest == hex::encode(owned.profile().capability_digest())
                && session.certificate_sha256 == hex::encode(ready.certificate_sha256())
                && session
                    .capabilities
                    .iter()
                    .map(String::as_str)
                    .eq(PROTECTED_RUNTIME_CAPABILITIES.iter().copied()),
        )
    }

    #[cfg(test)]
    fn verify_v3_renewal_frame(
        &self,
        renewal: &runne_api::ProtectedCredentialEnrollmentRenewRequestV3,
        frame: &[u8],
        now: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<VerifiedEnrollmentRenewalV3, LaunchAuthorityError> {
        let Self::V3 { owned, .. } = self else {
            return Err(LaunchAuthorityError::RenewalUnavailable);
        };
        renewal.verify_exact(owned, 0, keys)?;
        let ticket = runne_api::ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(frame)
            .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
        let verified = ticket.verify_exact_at(renewal, now, keys)?;
        Ok(VerifiedEnrollmentRenewalV3 {
            bootstrap_ticket: verified.bootstrap_ticket(),
            owned: verified.next_owned_launch(),
        })
    }

    fn verify_v3_shutdown_ack(
        &self,
        frame: &[u8],
        keys: &ProtectedActivationKeys,
    ) -> Result<bool, LaunchAuthorityError> {
        let Self::V3 { owned, .. } = self else {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        };
        let acknowledgement =
            runne_api::ProtectedCredentialEnrollmentShutdownAckV3::decode_frame(frame)
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
        acknowledgement.verify_exact(owned, keys)?;
        Ok(acknowledgement.graceful())
    }
}
