use runne_api::{
    ApiPrincipalId, PermissionControlAuthenticatorV1, PermissionControlContextV1,
    PermissionControlDirectionV1 as Direction, PermissionControlModeChallengeV1,
    PermissionControlPayloadV1 as Payload, PermissionControlPhaseV1 as Phase,
    PermissionControlPurposeV1 as Purpose, PermissionControlResultCodeV1,
    PermissionControlResultV1, PermissionModeNativePendingV2,
    permission_control_stable_subject_digest_v1,
};

#[path = "permission_control/owner.rs"]
mod owner;
#[cfg(all(test, feature = "test-support"))]
use owner::same_permission_channel;
use owner::{PermissionControlOwnerV1, permission_owner_identity, rebind_permission_sequence};
fn permission_wire_outer_frame(
    inner: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtectedBundledRuntimeError> {
    if inner.len() < 4
        || inner.len() > MAX_FRAME_PAYLOAD_BYTES
        || u32::from_be_bytes(inner[..4].try_into().unwrap_or([0; 4])) as usize != inner.len()
    {
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::InvalidContract,
        ));
    }
    let length = u32::try_from(inner.len()).map_err(|_| {
        ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::InvalidContract)
    })?;
    let mut wire = Zeroizing::new(Vec::with_capacity(inner.len() + 4));
    wire.extend_from_slice(&length.to_be_bytes());
    wire.extend_from_slice(inner);
    Ok(wire)
}
fn permission_wire_inner_frame(
    wire: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtectedBundledRuntimeError> {
    if wire.len() < 8
        || wire.len() > MAX_FRAME_PAYLOAD_BYTES + 4
        || u32::from_be_bytes(wire[..4].try_into().unwrap_or([0; 4])) as usize != wire.len() - 4
    {
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::InvalidContract,
        ));
    }
    let inner = &wire[4..];
    if u32::from_be_bytes(inner[..4].try_into().unwrap_or([0; 4])) as usize != inner.len() {
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::InvalidContract,
        ));
    }
    Ok(Zeroizing::new(inner.to_vec()))
}
/// Coordinator-owned sequence shared by mode and managed-policy frames.
/// It is bound to one verified process key owner and survives HTTP session rotation.
struct PermissionControlSequenceV1 {
    owner: PermissionControlOwnerV1,
    last_authenticated_sequence: u64,
    active: Option<PermissionModeExchangeV1>,
}

#[derive(Clone)]
struct PermissionModeExchangeV1 {
    owner: PermissionControlOwnerV1,
    context: PermissionControlContextV1,
    challenge: PermissionControlModeChallengeV1,
}

impl ProtectedBundledRuntimeSupervisor {
    /// Performs the protected-channel exchange before the caller releases its lock for UI or PAM.
    #[doc = "# Errors\nReturns an error for invalid lifecycle, ownership, or authenticated challenge state."]
    pub fn request_permission_mode_challenge(
        &mut self,
        pending: &PermissionModeNativePendingV2,
    ) -> Result<PermissionControlModeChallengeV1, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let owner = self
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .permission_control_owner()?;
        let sequence =
            self.permission_control_sequence
                .get_or_insert(PermissionControlSequenceV1 {
                    owner,
                    last_authenticated_sequence: 0,
                    active: None,
                });
        rebind_permission_sequence(sequence, owner)?;
        if sequence.active.is_some() {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let mut request_started = false;
        let result = {
            let process = self
                .process
                .as_mut()
                .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
            process.request_permission_mode_challenge(
                pending,
                sequence.last_authenticated_sequence,
                &mut request_started,
            )
        };
        let failed_after_send = result.is_err() && request_started;
        let output = match result {
            Ok((challenge, exchange, sequence_number)) => {
                sequence.last_authenticated_sequence = sequence_number;
                sequence.active = Some(exchange);
                Ok(challenge)
            }
            Err(error) => Err(error),
        };
        if failed_after_send {
            self.record_client_failure()?;
        }
        output
    }
}
impl ProtectedBundledRuntimeProcess {
    fn request_permission_mode_challenge(
        &mut self,
        pending: &PermissionModeNativePendingV2,
        previous_sequence: u64,
        request_started: &mut bool,
    ) -> Result<
        (
            PermissionControlModeChallengeV1,
            PermissionModeExchangeV1,
            u64,
        ),
        ProtectedBundledRuntimeError,
    > {
        let owner = self.permission_control_owner()?;
        let context = exact_request_context(pending, &self.activation, owner)?;
        let authenticator = PermissionControlAuthenticatorV1::from_protected_activation(
            &self.keys,
            Purpose::ModeControl,
        );
        let request_sequence = previous_sequence
            .checked_add(1)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let request = Zeroizing::new(
            authenticator
                .issue_frame(
                    context.clone(),
                    request_sequence,
                    Direction::DesktopToDaemon,
                    Payload::ModeRequest(runne_api::PermissionControlModeRequestV1),
                )
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?,
        );
        let mut challenge_context = context;
        challenge_context.predecessor_transcript_digest = Sha256::digest(&request[..]).into();
        let wire_request = permission_wire_outer_frame(&request)?;
        *request_started = true;
        write_frame(&mut self.channel, &wire_request)?;
        let wire_response = Zeroizing::new(read_frame(&mut self.channel)?);
        let response = permission_wire_inner_frame(&wire_response)?;
        let now = unix_millis()?;
        let authenticated = authenticator
            .authenticate_frame(
                &response,
                &challenge_context,
                Purpose::ModeControl,
                Phase::Challenge,
                Direction::DaemonToDesktop,
                previous_sequence,
                now,
            )
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let Payload::ModeChallenge(challenge) = authenticated.payload() else {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        };
        let workspace = uuid::Uuid::parse_str(&pending.workspace_id)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if workspace.to_string() != pending.workspace_id
            || challenge.principal != pending.principal_id
            || challenge.workspace_id != *workspace.as_bytes()
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let challenge_frame_digest = Sha256::digest(&response[..]).into();
        let mut consent_context = challenge_context;
        consent_context.predecessor_transcript_digest = challenge_frame_digest;
        Ok((
            challenge.clone(),
            PermissionModeExchangeV1 {
                owner,
                context: consent_context,
                challenge: challenge.clone(),
            },
            authenticated.sequence(),
        ))
    }

    fn permission_control_owner(
        &self,
    ) -> Result<PermissionControlOwnerV1, ProtectedBundledRuntimeError> {
        let (_, (authority, desktop, daemon, generation, session)) =
            permission_owner_identity(&self.activation)?;
        let epoch = self
            .keys
            .permission_control_native_authenticator()
            .native_key_epoch();
        Ok((authority, desktop, daemon, generation, epoch, session))
    }
}
include!("permission_control/native_signer.rs");
fn exact_request_context(
    pending: &PermissionModeNativePendingV2,
    activation: &ProtectedProcessActivation,
    owner: PermissionControlOwnerV1,
) -> Result<PermissionControlContextV1, ProtectedBundledRuntimeError> {
    let (stable, _) = permission_owner_identity(activation)?;
    let principal = ApiPrincipalId::new(stable.principal_id().to_owned())
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    let stable_subject = permission_control_stable_subject_digest_v1(&principal)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    let source = &pending.context;
    if pending.principal_id != principal.as_str()
        || source.runtime_authority != hex::encode(stable.authority_id())
        || source.store_lineage_id != *stable.lineage_id()
        || source.stable_subject_digest != stable_subject
        || source.protected_launch_authority_id != owner.0
        || source.desktop_authority_id != owner.1
        || source.daemon_instance_id != owner.2
        || source.protected_session_id != owner.5
        || source.launch_generation != owner.3
        || source.native_key_epoch != owner.4
    {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    source
        .control_context()
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
}
#[cfg(all(test, feature = "test-support"))]
#[path = "permission_control_tests.rs"]
mod permission_control_tests;
#[cfg(feature = "test-support")]
include!("permission_control/test_support.rs");
#[cfg(all(test, feature = "test-support"))]
#[path = "permission_control_test_support_tests.rs"]
mod permission_control_test_support_tests;
