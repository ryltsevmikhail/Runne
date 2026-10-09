use super::{ProtectedActivationChannel, ProtectedRootControl};
use runne_api::{
    LaunchAuthorityError, PermissionControlAuthenticatorV1 as Authenticator,
    PermissionControlDirectionV1 as Direction, PermissionControlPayloadV1 as Payload,
    PermissionControlPhaseV1 as Phase, PermissionControlPurposeV1 as Purpose,
    ProtectedActivationKeys, ProtectedOwnedLaunchV1, RuntimeSessionBinding,
};
use sha2::Digest;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn permission_wire_inner_frame(
    frame: &[u8],
) -> Result<Option<&[u8]>, LaunchAuthorityError> {
    if frame.len() < 8 {
        return Ok(None);
    }
    let outer_length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    ) as usize;
    if outer_length != frame.len() - 4 {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    let inner = &frame[4..];
    let inner_length = u32::from_be_bytes(
        inner[..4]
            .try_into()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    ) as usize;
    if inner_length != inner.len() {
        return Ok(None);
    }
    Ok(Some(inner))
}

pub(super) fn permission_wire_outer_frame(inner: &[u8]) -> Result<Vec<u8>, LaunchAuthorityError> {
    if inner.len() < 4
        || u32::from_be_bytes(
            inner[..4]
                .try_into()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
        ) as usize
            != inner.len()
    {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    let length = u32::try_from(inner.len()).map_err(|_| LaunchAuthorityError::InvalidContract)?;
    let mut wire = Vec::with_capacity(inner.len() + 4);
    wire.extend_from_slice(&length.to_be_bytes());
    wire.extend_from_slice(inner);
    Ok(wire)
}

#[cfg(all(unix, feature = "desktop-protected"))]
pub(super) struct PermissionModeExchange {
    command_id: runne_domain::id::CommandId,
    workspace: runne_domain::id::WorkspaceId,
    context: runne_api::PermissionControlContextV1,
    challenge_frame_digest: [u8; 32],
}

#[cfg(all(unix, feature = "desktop-protected"))]
pub(super) fn dispatch_permission_mode_request(
    channel: &mut ProtectedActivationChannel,
    frame: &[u8],
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV1,
    previous_sequence: u64,
    active: &mut Option<PermissionModeExchange>,
    root_control: Option<&ProtectedRootControl>,
) -> Result<Option<u64>, LaunchAuthorityError> {
    let Some(root_control) = root_control else {
        return Ok(None);
    };
    let Some(frame) = permission_wire_inner_frame(frame)? else {
        return Ok(None);
    };
    let auth = Authenticator::from_protected_activation(keys, Purpose::ModeControl);
    let now = permission_control_now_millis()?;
    let principal = runne_api::ApiPrincipalId::new(owned.stable().principal_id().to_owned())
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    if let Ok(hint) = auth.mode_request_routing_hint(frame, previous_sequence, now) {
        if active.is_some() {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let Some((mut context, challenge)) =
            root_control.permission_mode_challenge(&principal, hint.command_id())?
        else {
            return Ok(None);
        };
        let authenticated = auth
            .authenticate_frame(
                frame,
                &context,
                Purpose::ModeControl,
                Phase::Request,
                Direction::DesktopToDaemon,
                previous_sequence,
                now,
            )
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
        if !matches!(authenticated.payload(), Payload::ModeRequest(_)) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        context.predecessor_transcript_digest = sha2::Sha256::digest(frame).into();
        let response = auth
            .issue_frame(
                context.clone(),
                authenticated.sequence(),
                Direction::DaemonToDesktop,
                Payload::ModeChallenge(challenge.clone()),
            )
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
        let wire_response = permission_wire_outer_frame(&response)?;
        channel.write_control_frame(&wire_response)?;
        *active = Some(PermissionModeExchange {
            command_id: hint.command_id(),
            workspace: runne_domain::id::WorkspaceId::from_bytes(challenge.workspace_id),
            context,
            challenge_frame_digest: sha2::Sha256::digest(&response).into(),
        });
        return Ok(Some(authenticated.sequence()));
    }

    let consent_hint = auth
        .mode_consent_routing_hint(frame, previous_sequence, now)
        .ok();
    let cancel_hint = auth
        .mode_cancel_routing_hint(frame, previous_sequence, now)
        .ok();
    let Some(exchange) = active.as_ref() else {
        return Ok(None);
    };
    let Some(command_id) = consent_hint
        .as_ref()
        .map(|hint| hint.command_id())
        .or_else(|| cancel_hint.as_ref().map(|hint| hint.command_id()))
    else {
        return Ok(None);
    };
    if command_id != exchange.command_id {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    let phase = if consent_hint.is_some() {
        Phase::Consent
    } else {
        Phase::Cancel
    };
    let direction = Direction::DesktopToDaemon;
    let mut expected = exchange.context.clone();
    expected.predecessor_transcript_digest = exchange.challenge_frame_digest;
    let authenticated = auth
        .authenticate_frame(
            frame,
            &expected,
            Purpose::ModeControl,
            phase,
            direction,
            previous_sequence,
            now,
        )
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    let result = match authenticated.payload() {
        Payload::ModeConsent(consent) => root_control
            .finish_permission_mode(
                &principal,
                exchange.workspace,
                &expected,
                consent,
                keys,
                now,
            )?
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?,
        Payload::Cancel => root_control
            .cancel_permission_mode(&principal, exchange.workspace, &expected)?
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?,
        _ => return Err(LaunchAuthorityError::OwnershipMismatch),
    };
    expected.predecessor_transcript_digest = sha2::Sha256::digest(frame).into();
    let response = auth
        .issue_frame(
            expected,
            authenticated.sequence(),
            Direction::DaemonToDesktop,
            Payload::Result(result),
        )
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    let wire_response = permission_wire_outer_frame(&response)?;
    channel.write_control_frame(&wire_response)?;
    *active = None;
    Ok(Some(authenticated.sequence()))
}

fn permission_control_now_millis() -> Result<u64, LaunchAuthorityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
}

pub(super) fn owner_matches_current_session(
    owned: &ProtectedOwnedLaunchV1,
    current: &RuntimeSessionBinding,
) -> bool {
    current.ephemeral().session_id() == owned.session_id()
        && current.ephemeral().daemon_instance_id().into_bytes() == *owned.daemon_instance_id()
        && current.ephemeral().launch_generation() == owned.launch_generation()
        && current.stable().authority_id() == owned.stable().authority_id()
        && current.stable().principal_id().as_str() == owned.stable().principal_id()
        && current.stable().lineage_id().as_bytes() == owned.stable().lineage_id()
}
