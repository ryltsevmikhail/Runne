use super::*;

/// Receives one descriptor after an authenticated offer on the already-owned control channel.
/// A broken native transfer closes the launch; a semantic rejection emits a signed result.
pub fn receive_root_handle_offer(
    channel: &mut ProtectedActivationChannel,
    frame: &[u8],
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV1,
    now_unix_millis: u64,
) -> Result<(), LaunchAuthorityError> {
    let (sender_pid, effective_uid) = channel.peer_identity()?;
    let receiver_pid = std::process::id();
    let authenticator = RootHandleTransferAuthenticator::from_protected_activation(keys);
    let offer = RootHandleControlFrame::decode_offer_for_receiver(
        frame,
        &authenticator,
        owned.launch_authority_id(),
        owned.session_id(),
        owned.launch_generation(),
        sender_pid,
        receiver_pid,
        effective_uid,
        now_unix_millis,
    )?;
    let ready = RootHandleTransferReady::new(&offer, &authenticator);
    channel.write_control_frame(&RootHandleControlFrame::Ready(ready).encode())?;
    let binding =
        gocode_platform_desktop::binding_for_protected_control(offer.context(), offer.digest())
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    let root = gocode_platform_desktop::receive_on_protected_channel(
        channel.native_stream(),
        &authenticator,
        &binding,
    )
    .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    let result = gocode_api::RootHandleTransferResult::new(
        &RootHandleTransferReady::new(&offer, &authenticator),
        false,
        &authenticator,
    );
    channel.write_control_frame(&RootHandleControlFrame::Result(result).encode())?;
    drop(root);
    Ok(())
}
