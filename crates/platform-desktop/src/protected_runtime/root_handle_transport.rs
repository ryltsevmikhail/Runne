#[cfg(unix)]
impl ProtectedBundledRuntimeProcess {
    /// Transfers one verified root only over this process' authenticated inherited channel.
    ///
    /// The caller receives no filesystem path, descriptor, or admission claim.
    ///
    /// # Errors
    ///
    /// Returns a closed error for any stale process, control proof, peer, descriptor,
    /// or semantic-rejection failure.
    pub fn prepare_root_handle(
        &mut self,
        root: &crate::VerifiedRootHandle,
        workspace_id: gocode_domain::id::WorkspaceId,
        expected_version: u64,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.graceful_requested { return Err(ProtectedBundledRuntimeError::InvalidState); }
        let receiver_pid = self.child.id();
        let sender_pid = std::process::id();
        let effective_uid = rustix::process::geteuid().as_raw();
        let now = unix_millis()?;
        let expires = now.checked_add(30_000).ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let context = gocode_api::RootHandleTransferContext::new(
            *self.activation.compatibility_owned().launch_authority_id(),
            *self.activation.compatibility_owned().session_id(),
            self.activation.compatibility_owned().launch_generation(), sender_pid, receiver_pid,
            effective_uid, workspace_id, expected_version, *uuid::Uuid::now_v7().as_bytes(), now, expires,
        )?;
        let authenticator = gocode_api::RootHandleTransferAuthenticator::from_protected_activation(&self.keys);
        let offer = gocode_api::RootHandleTransferOffer::new(context.clone(), 1, &authenticator)?;
        let offer_digest = offer.digest();
        write_frame(&mut self.channel, &gocode_api::RootHandleControlFrame::Offer(offer).encode())?;
        let ready = gocode_api::RootHandleControlFrame::decode_and_verify(
            &read_frame(&mut self.channel)?, &authenticator, &context, 1, unix_millis()?,
        )?;
        let gocode_api::RootHandleControlFrame::Ready(ready) = ready else {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::InvalidContract));
        };
        if ready.offer_digest() != &offer_digest {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let binding = crate::root_handle_broker::binding_for_protected_control(&context, *ready.offer_digest())
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        crate::root_handle_broker::send_on_protected_channel(
            &mut self.channel, root, &authenticator, &binding,
        ).map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let result = gocode_api::RootHandleControlFrame::decode_and_verify(
            &read_frame(&mut self.channel)?, &authenticator, &context, 2, unix_millis()?,
        )?;
        let gocode_api::RootHandleControlFrame::Result(result) = result else {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::InvalidContract));
        };
        if result.offer_digest() != ready.offer_digest() || !result.accepted() {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        Ok(())
    }
}
