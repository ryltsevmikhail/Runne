// Desktop half of the same-process V2→V3 enrollment control transition.
//
// The desktop proves its V2 enrollment claims on the entered control channel,
// verifies the daemon-issued prelude against its own V2 keys, and answers
// with the exact V3 launch request whose broker commitment binds the prelude.
// Readiness replaces the process state: every later frame speaks V3.

#[cfg(unix)]
use runne_api::{
    CredentialBrokerTransferAuthenticator, DaemonEnrollmentLaunchPreludeV1,
    ProtectedCredentialEnrollmentLaunchBindingV1, ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentPreludeV2, ProtectedCredentialEnrollmentPrepareV2,
    ProtectedCredentialEnrollmentReadyV3,
};

/// Desktop-held enrollment claims for exactly one transition attempt.
///
/// Every digest is measured from the retained installed release tuple and the
/// live desktop peer; the daemon independently revalidates each native fact.
pub struct EnrollmentTransitionClaims {
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    desktop_peer_binding_digest: [u8; 32],
    desktop_supervisor_generation: u64,
}

impl EnrollmentTransitionClaims {
    #[must_use] pub const fn new(
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
    ) -> Self {
        Self {
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
        }
    }
}

/// Bounded continuous-clock validity for the V3 launch request.
const ENROLLMENT_REQUEST_TTL_MILLIS: u64 = 20_000;

fn random_nonce() -> Option<[u8; 32]> {
    use rand::{RngCore, rngs::OsRng};
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    (nonce != [0; 32]).then_some(nonce)
}

const fn launch_error(error: LaunchAuthorityError) -> ProtectedBundledRuntimeError {
    ProtectedBundledRuntimeError::LaunchAuthority(error)
}

impl ProtectedBundledRuntimeProcess {
    /// Upgrades this exact V2 process to the V3 enrollment protocol in place.
    ///
    /// The exchange never re-enters the channel handshake: the daemon already
    /// admitted this transcript and answers on the same socket. Any failure
    /// after the prepare write leaves the daemon's state ambiguous, so the
    /// child is fenced exactly like an ambiguous V3 renewal.
    /// Assembles the Linux local-runtime enrollment claims from the live V2
    /// launch: the release tuple digests are measured from the exact staged
    /// daemon binary, and the peer binding digest from this process.
    #[cfg(unix)]
    pub(crate) fn begin_local_linux_enrollment_claims(
        &self,
    ) -> Result<EnrollmentTransitionClaims, ProtectedBundledRuntimeError> {
        use sha2::{Digest, Sha256};

        const RELEASE_TUPLE_DOMAIN: &[u8] = b"runne/linux-release-tuple/v1\0";
        const QUALIFICATION_DOMAIN: &[u8] = b"runne/linux-qualification-binding/v1\0";

        let (compatibility, owned) = match &self.activation {
            ProtectedProcessActivation::V2 { request, owned, .. } => {
                (request.compatibility_request().clone(), owned.clone())
            }
            _ => return Err(ProtectedBundledRuntimeError::InvalidState),
        };
        let launch_authority = compatibility.launch_authority_id();
        let desktop_host = compatibility.desktop_host_instance_id();
        let daemon_executable_sha256 = compatibility.executable().executable_sha256();
        let supervisor_generation = owned.launch_generation();
        let mut hasher = Sha256::new();
        hasher.update(RELEASE_TUPLE_DOMAIN);
        hasher.update(daemon_executable_sha256);
        hasher.update(supervisor_generation.to_le_bytes());
        let release_tuple_digest: [u8; 32] = hasher.finalize().into();
        let mut hasher = Sha256::new();
        hasher.update(QUALIFICATION_DOMAIN);
        hasher.update(release_tuple_digest);
        let qualification_binding_digest: [u8; 32] = hasher.finalize().into();
        let desktop_peer_binding_digest =
            crate::protected_runtime::linux_enrollment_peer::linux_enrollment_peer_binding(
                release_tuple_digest,
                launch_authority,
                desktop_host,
                supervisor_generation,
            )
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        Ok(EnrollmentTransitionClaims::new(
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            supervisor_generation,
        ))
    }

    #[cfg(unix)]
    pub(crate) fn begin_credential_enrollment_transition(
        &mut self,
        claims: &EnrollmentTransitionClaims,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        if self.graceful_requested {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let (compatibility, owned) = match &self.activation {
            ProtectedProcessActivation::V2 { request, owned, .. } => {
                (request.compatibility_request().clone(), owned.clone())
            }
            _ => return Err(ProtectedBundledRuntimeError::InvalidState),
        };
        let mut request_started = false;
        let result = self.run_enrollment_transition_exchange(claims, &compatibility, &owned, &mut request_started);
        if result.is_err() && request_started {
            self.fence_ambiguous_transition();
        }
        result
    }

    #[cfg(unix)]
    fn run_enrollment_transition_exchange(
        &mut self,
        claims: &EnrollmentTransitionClaims,
        compatibility: &ProtectedLaunchRequestV1,
        owned: &ProtectedOwnedLaunchV2,
        request_started: &mut bool,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        let nonce = random_nonce().ok_or_else(|| {
            launch_error(LaunchAuthorityError::RenewalUnavailable)
        })?;
        let mut prepare = ProtectedCredentialEnrollmentPrepareV2::new(
            owned.clone(),
            1,
            nonce,
            claims.release_tuple_digest,
            claims.qualification_binding_digest,
            claims.desktop_peer_binding_digest,
            claims.desktop_supervisor_generation,
        )
        .map_err(launch_error)?;
        prepare.sign(&self.keys);
        write_frame(
            &mut self.channel,
            &Zeroizing::new(
                prepare
                    .encode_frame()
                    .map_err(|_| launch_error(LaunchAuthorityError::InvalidContract))?,
            ),
        )?;
        *request_started = true;

        let frame = Zeroizing::new(read_frame(&mut self.channel)?);
        let signed_prelude =
            ProtectedCredentialEnrollmentPreludeV2::decode_frame(&frame)
                .map_err(|_| launch_error(LaunchAuthorityError::RenewalUnavailable))?;
        let now = unix_wall_millis()
            .map_err(|_| launch_error(LaunchAuthorityError::RenewalUnavailable))?;
        signed_prelude
            .verify_exact_at(&prepare, owned, 0, now, &self.keys)
            .map_err(launch_error)?;
        let prelude = signed_prelude.prelude().clone();
        // The verified prelude commits this daemon to one exact rendezvous;
        // the later broker writer handoff binds every offer to these facts.
        self.enrollment_broker_facts = Some(EnrollmentBrokerFacts::new(
            prelude.channel_binding(),
            prelude.publication_key(),
        ));

        let mut v3 = Self::build_enrollment_v3_request(claims, compatibility, owned, &prelude, now)?;
        write_frame(
            &mut self.channel,
            &Zeroizing::new(
                v3.encode_frame()
                    .map_err(|_| launch_error(LaunchAuthorityError::InvalidContract))?,
            ),
        )?;

        let frame = Zeroizing::new(read_frame(&mut self.channel)?);
        let v3_keys = v3.derive_keys_and_forget();
        let ready = ProtectedCredentialEnrollmentReadyV3::decode_frame(&frame)
            .map_err(|_| launch_error(LaunchAuthorityError::ReadinessProofMismatch))?;
        ready.verify_exact(&v3, &v3_keys).map_err(launch_error)?;
        let owned_v3 = ready.owned_launch();
        let profile =
            ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &v3, now, &v3_keys)
                .map_err(launch_error)?;
        self.keys = v3_keys;
        self.activation = ProtectedProcessActivation::V3 {
            request: v3,
            ready,
            owned: owned_v3,
        };
        Ok(profile)
    }

    /// Builds the V3 launch request bound to the verified prelude: the fresh
    /// launch secret, the binding chosen by the daemon's prelude platform,
    /// and the commitment over the exact V3 keys.
    #[cfg(unix)]
    fn build_enrollment_v3_request(
        claims: &EnrollmentTransitionClaims,
        compatibility: &ProtectedLaunchRequestV1,
        owned: &ProtectedOwnedLaunchV2,
        prelude: &DaemonEnrollmentLaunchPreludeV1,
        now: u64,
    ) -> Result<ProtectedCredentialEnrollmentLaunchRequestV3, ProtectedBundledRuntimeError> {
        let secret = random_nonce().ok_or_else(|| {
            launch_error(LaunchAuthorityError::RenewalUnavailable)
        })?;
        let v1_request = ProtectedLaunchRequestV1::new(
            compatibility.launch_authority_id(),
            compatibility.desktop_host_instance_id(),
            LaunchSecret::from_bytes(secret)
                .map_err(|_| launch_error(LaunchAuthorityError::InvalidContract))?,
            now,
            now.saturating_add(ENROLLMENT_REQUEST_TTL_MILLIS),
            compatibility.principal_id(),
            compatibility.profile().clone(),
            compatibility.executable().clone(),
            compatibility.runtime_root().to_path_buf(),
            ActivationDispositionV1::Existing(Box::new(
                owned.compatibility_owned_launch().stable().clone(),
            )),
        )
        .map_err(launch_error)?;
        let v3_keys = v1_request.derive_keys();
        let commitment = CredentialBrokerTransferAuthenticator::from_protected_activation(&v3_keys)
            .enrollment_launch_commitment(prelude);
        let binding = if prelude.platform() == 2 {
            ProtectedCredentialEnrollmentLaunchBindingV1::linux_arm64(
                *prelude.installation_identity_digest(),
                claims.release_tuple_digest,
                claims.qualification_binding_digest,
                claims.desktop_peer_binding_digest,
                claims.desktop_supervisor_generation,
                commitment,
            )
        } else {
            ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
                *prelude.installation_identity_digest(),
                claims.release_tuple_digest,
                claims.qualification_binding_digest,
                claims.desktop_peer_binding_digest,
                claims.desktop_supervisor_generation,
                commitment,
            )
        }
        .map_err(launch_error)?;
        ProtectedCredentialEnrollmentLaunchRequestV3::new(
            v1_request,
            owned.provider_binding().clone(),
            binding,
        )
        .map_err(launch_error)
    }

    fn fence_ambiguous_transition(&mut self) {
        self.graceful_requested = true;
        self.graceful_acknowledged = false;
        #[cfg(unix)]
        {
            use std::net::Shutdown;
            let _ = self.channel.shutdown(Shutdown::Both);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Unix wall-clock milliseconds: the enrollment TTLs are short (20 s) and the
/// daemon compares the same wall-clock domain.
#[cfg(unix)]
fn unix_wall_millis() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .map_err(|_| LaunchAuthorityError::StaleLaunchAuthority)
}
