use super::*;

/// Receives one descriptor after an authenticated offer on the already-owned control channel.
/// A broken native transfer closes the launch; a semantic rejection emits a signed result.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_root_handle_control_frame(
    channel: &mut ProtectedActivationChannel,
    frame: &[u8],
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV1,
    used_transfers: &mut std::collections::VecDeque<([u8; 16], [u8; 32], u64)>,
    previous_sequence: u64,
    now_unix_millis: u64,
    authority: Option<&ProtectedRootControl>,
) -> Result<Option<u64>, LaunchAuthorityError> {
    dispatch_root_handle_control_frame_for_ids(
        channel,
        frame,
        keys,
        owned.launch_authority_id(),
        owned.session_id(),
        owned.launch_generation(),
        used_transfers,
        previous_sequence,
        now_unix_millis,
        authority,
    )
}

/// Same dispatch for launches that keep the three binding identities without a
/// V1 owned launch (e.g. the V3 enrollment-owned launch).
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_root_handle_control_frame_for_ids(
    channel: &mut ProtectedActivationChannel,
    frame: &[u8],
    keys: &ProtectedActivationKeys,
    launch_authority_id: &[u8; 16],
    session_id: &[u8; 16],
    launch_generation: u64,
    used_transfers: &mut std::collections::VecDeque<([u8; 16], [u8; 32], u64)>,
    previous_sequence: u64,
    now_unix_millis: u64,
    authority: Option<&ProtectedRootControl>,
) -> Result<Option<u64>, LaunchAuthorityError> {
    if !runne_api::is_root_handle_control_frame(frame) {
        return Ok(None);
    }
    let sequence = receive_root_handle_offer_for_ids(
        channel,
        frame,
        keys,
        launch_authority_id,
        session_id,
        launch_generation,
        used_transfers,
        previous_sequence,
        now_unix_millis,
        authority,
    )?;
    Ok(Some(sequence))
}

/// Same dispatch for launches that keep the three binding identities without a
/// V1 owned launch (e.g. the V3 enrollment-owned launch).
#[allow(clippy::too_many_arguments)]
#[expect(
    dead_code,
    reason = "the launch path that consumes root-handle offers lands with a later composition slice"
)]
pub(crate) fn receive_root_handle_offer(
    channel: &mut ProtectedActivationChannel,
    frame: &[u8],
    keys: &ProtectedActivationKeys,
    launch_authority_id: &[u8; 16],
    session_id: &[u8; 16],
    launch_generation: u64,
    used_transfers: &mut std::collections::VecDeque<([u8; 16], [u8; 32], u64)>,
    previous_sequence: u64,
    now_unix_millis: u64,
    authority: Option<&ProtectedRootControl>,
) -> Result<Option<u64>, LaunchAuthorityError> {
    if !runne_api::is_root_handle_control_frame(frame) {
        return Ok(None);
    }
    let sequence = receive_root_handle_offer_for_ids(
        channel,
        frame,
        keys,
        launch_authority_id,
        session_id,
        launch_generation,
        used_transfers,
        previous_sequence,
        now_unix_millis,
        authority,
    )?;
    Ok(Some(sequence))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_root_handle_offer_for_ids(
    channel: &mut ProtectedActivationChannel,
    frame: &[u8],
    keys: &ProtectedActivationKeys,
    launch_authority_id: &[u8; 16],
    session_id: &[u8; 16],
    launch_generation: u64,
    used_transfers: &mut std::collections::VecDeque<([u8; 16], [u8; 32], u64)>,
    previous_sequence: u64,
    now_unix_millis: u64,
    authority: Option<&ProtectedRootControl>,
) -> Result<u64, LaunchAuthorityError> {
    receive_root_handle_offer_for_ids(
        channel,
        frame,
        keys,
        owned.launch_authority_id(),
        owned.session_id(),
        owned.launch_generation(),
        used_transfers,
        previous_sequence,
        now_unix_millis,
        authority,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_root_handle_offer_for_ids(
    channel: &mut ProtectedActivationChannel,
    frame: &[u8],
    keys: &ProtectedActivationKeys,
    launch_authority_id: &[u8; 16],
    session_id: &[u8; 16],
    launch_generation: u64,
    used_transfers: &mut std::collections::VecDeque<([u8; 16], [u8; 32], u64)>,
    previous_sequence: u64,
    now_unix_millis: u64,
    authority: Option<&ProtectedRootControl>,
) -> Result<u64, LaunchAuthorityError> {
    let (sender_pid, effective_uid) = channel.peer_identity()?;
    let receiver_pid = std::process::id();
    let authenticator = RootHandleTransferAuthenticator::from_protected_activation(keys);
    let offer = RootHandleControlFrame::decode_offer_for_receiver(
        frame,
        &authenticator,
        launch_authority_id,
        session_id,
        launch_generation,
        sender_pid,
        receiver_pid,
        effective_uid,
        previous_sequence,
        now_unix_millis,
    )?;
    retain_transfer(used_transfers, &offer, now_unix_millis)?;
    let ready = RootHandleTransferReady::new(&offer, &authenticator);
    channel.write_control_frame(&RootHandleControlFrame::Ready(ready).encode_frame())?;
    let mut endpoint =
        channel.root_handle_endpoint(authenticator.clone(), offer.context(), offer.digest())?;
    let root = endpoint
        .receive()
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    endpoint
        .finish()
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    let ready = RootHandleTransferReady::new(&offer, &authenticator);
    let result = match authority.and_then(|value| {
        value
            .admit_verified_offer(&offer, root, now_unix_millis)
            .ok()
    }) {
        Some(issued) => {
            let (admission, _) = issued.into_parts();
            runne_api::RootHandleTransferResult::admitted(&ready, admission, &authenticator)
        }
        None => runne_api::RootHandleTransferResult::rejected(&ready, &authenticator),
    };
    channel.write_control_frame(&RootHandleControlFrame::Result(result).encode_frame())?;
    previous_sequence
        .checked_add(3)
        .ok_or(LaunchAuthorityError::RenewalReplay)
}

fn retain_transfer(
    used: &mut std::collections::VecDeque<([u8; 16], [u8; 32], u64)>,
    offer: &runne_api::RootHandleTransferOffer,
    now: u64,
) -> Result<(), LaunchAuthorityError> {
    while used.front().is_some_and(|entry| entry.2 < now) {
        used.pop_front();
    }
    let id = *offer.context().transfer_id();
    if used.iter().any(|entry| entry.0 == id) || used.len() >= 64 {
        return Err(LaunchAuthorityError::RenewalReplay);
    }
    used.push_back((id, offer.digest(), offer.context().expires_at_unix_millis()));
    Ok(())
}
