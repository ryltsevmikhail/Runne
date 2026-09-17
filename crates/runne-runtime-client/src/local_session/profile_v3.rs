use runne_api::{
    ProtectedCredentialEnrollmentLaunchRequestV3, ProtectedCredentialEnrollmentReadyV3,
    ProtectedCredentialEnrollmentRenewRequestV3, ProtectedCredentialEnrollmentRenewTicketV3,
};

impl ProtectedBundledRuntimeProfile {
    /// # Errors
    /// Returns a closed error for a stale or non-exact native V3 readiness tuple.
    pub fn from_ready_v3(
        ready: &ProtectedCredentialEnrollmentReadyV3,
        request: &ProtectedCredentialEnrollmentLaunchRequestV3,
        now_unix_millis: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<Self, LaunchAuthorityError> {
        request.validate_freshness(now_unix_millis)?;
        ready.verify_exact(request, keys)?;
        Ok(Self {
            peer: session_peer_from_v3_ready(ready, request)?,
            bootstrap_key: keys.bootstrap_key(),
            enrollment_owned_launch: Some(ready.owned_launch()),
        })
    }

    /// # Errors
    /// Returns a closed error for a stale, replayed, or non-exact V3 renewal.
    ///
    /// `now_macos_continuous_millis` must come from macOS `mach_continuous_time`
    /// in the same OS-wide boot domain as the signed ticket's issued/expires
    /// values; that clock advances during sleep. This function does not source time.
    #[allow(clippy::too_many_arguments)] // Exact native tuple; do not collapse authority inputs.
    pub fn from_renewal_v3(
        ready: &ProtectedCredentialEnrollmentReadyV3,
        launch: &ProtectedCredentialEnrollmentLaunchRequestV3,
        current_owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        renewal: &ProtectedCredentialEnrollmentRenewRequestV3,
        ticket: &ProtectedCredentialEnrollmentRenewTicketV3,
        now_macos_continuous_millis: u64,
        last_renewal_sequence: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<Self, LaunchAuthorityError> {
        ready.verify_exact(launch, keys)?;
        if !current_owned_matches_ready(current_owned, ready) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        renewal.verify_exact(current_owned, last_renewal_sequence, keys)?;
        let verified = ticket.verify_exact_at(renewal, now_macos_continuous_millis, keys)?;
        let mut peer = session_peer_from_v3_ready(ready, launch)?;
        peer.expected_session_id = Some(*verified.next_session_id());
        Ok(Self {
            peer,
            bootstrap_key: verified.bootstrap_ticket(),
            enrollment_owned_launch: Some(verified.next_owned_launch()),
        })
    }

    /// Returns the exact V3 state required for the next daemon-owned control frame.
    #[must_use]
    pub const fn enrollment_owned_launch(
        &self,
    ) -> Option<&ProtectedCredentialEnrollmentOwnedLaunchV3> {
        self.enrollment_owned_launch.as_ref()
    }
}

fn current_owned_matches_ready(
    current: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    ready: &ProtectedCredentialEnrollmentReadyV3,
) -> bool {
    let initial = ready.owned_launch();
    current.launch_authority_id() == initial.launch_authority_id()
        && current.desktop_host_instance_id() == initial.desktop_host_instance_id()
        && current.daemon_instance_id() == initial.daemon_instance_id()
        && current.launch_generation() == initial.launch_generation()
        && current.executable() == initial.executable()
        && current.profile() == initial.profile()
        && current.stable() == initial.stable()
        && current.provider_binding() == initial.provider_binding()
        && current.enrollment_binding() == initial.enrollment_binding()
}

fn session_peer_from_v3_ready(
    ready: &ProtectedCredentialEnrollmentReadyV3,
    request: &ProtectedCredentialEnrollmentLaunchRequestV3,
) -> Result<SessionPeer, LaunchAuthorityError> {
    let schema_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(LaunchAuthorityError::ProfileHashMismatch)?;
    let profile = ready.profile();
    let stable = ready.stable();
    if profile.transport_profile_id() != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        || profile.runtime_profile_schema_version() != PROTECTED_RUNTIME_PROFILE_SCHEMA_VERSION
        || profile.profile_id() != crate::EXPECTED_BUNDLE_ID
        || profile.profile_hash() != &schema_hash
        || stable.principal_id() != request.principal_id()
        || stable.profile_id() != profile.profile_id()
        || stable.profile_hash() != profile.profile_hash()
        || stable.capability_digest() != profile.capability_digest()
        || !exact_protected_capability_profile(ready.capabilities())
        || ordered_capability_digest(ready.capabilities()) != *profile.capability_digest()
    {
        return Err(LaunchAuthorityError::ProfileHashMismatch);
    }
    let certificate_digest: [u8; 32] = Sha256::digest(ready.certificate_der()).into();
    if &certificate_digest != ready.certificate_sha256() {
        return Err(LaunchAuthorityError::ReadinessProofMismatch);
    }
    let (endpoint, origin) =
        parse_endpoint(ready.endpoint()).map_err(|_| LaunchAuthorityError::InvalidContract)?;
    Ok(SessionPeer {
        endpoint,
        origin,
        certificate_der: ready.certificate_der().to_vec(),
        certificate_sha256: *ready.certificate_sha256(),
        executable_sha256: *ready.executable().executable_sha256(),
        launch_authority_id: request.launch_authority_id(),
        authority_id: *stable.authority_id(),
        principal_id: stable.principal_id().to_owned(),
        event_log_lineage_id: uuid::Uuid::from_bytes(*stable.lineage_id()),
        daemon_instance_id: uuid::Uuid::from_bytes(*ready.daemon_instance_id()),
        launch_generation: ready.launch_generation(),
        // Every daemon launch starts at authorization epoch 0 and the
        // enrollment transition raises it by exactly one before this
        // profile is produced.
        expected_authorization_epoch: 1,
        expected_session_id: Some(*ready.session_id()),
        schema_hash: *profile.profile_hash(),
        capabilities: ready.capabilities().to_vec(),
        capability_digest: *profile.capability_digest(),
        provider_binding: Some(ready.provider_binding().clone()),
    })
}
