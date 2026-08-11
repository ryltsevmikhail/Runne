#[cfg(all(unix, feature = "protected-channel-integration"))]
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
        let transaction = self.root_handle_preflight(workspace_id, expected_version)?;
        match self.prepare_root_handle_transaction(root, transaction) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ProtectedBundledRuntimeError::OwnershipMismatch),
            Err(error) => { self.poison_root_transport(); Err(error) }
        }
    }

    fn root_handle_preflight(
        &self,
        workspace_id: gocode_domain::id::WorkspaceId,
        expected_version: u64,
    ) -> Result<RootHandleTransaction, ProtectedBundledRuntimeError> {
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
        let sequence = self.root_control_sequence.checked_add(1)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let offer = gocode_api::RootHandleTransferOffer::new(context.clone(), sequence, &authenticator)?;
        Ok(RootHandleTransaction { authenticator, context, sequence, offer })
    }

    fn prepare_root_handle_transaction(
        &mut self,
        root: &crate::VerifiedRootHandle,
        transaction: RootHandleTransaction,
    ) -> Result<bool, ProtectedBundledRuntimeError> {
        let RootHandleTransaction { authenticator, context, sequence, offer } = transaction;
        let offer_digest = offer.digest();
        write_frame(
            &mut self.channel,
            &gocode_api::RootHandleControlFrame::Offer(offer).encode_frame(),
        )?;
        let ready = gocode_api::RootHandleControlFrame::decode_and_verify(
            &read_frame(&mut self.channel)?, &authenticator, &context, sequence, unix_millis()?,
        )?;
        let gocode_api::RootHandleControlFrame::Ready(ready) = ready else {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::InvalidContract));
        };
        if ready.offer_digest() != &offer_digest {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let mut endpoint = crate::ProtectedRootHandleEndpoint::from_owned_protected_channel(
            self.channel.try_clone().map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?,
            authenticator.clone(), &context, *ready.offer_digest(),
        ).map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        endpoint.send(root).map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        endpoint.finish().map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let result = gocode_api::RootHandleControlFrame::decode_and_verify(
            &read_frame(&mut self.channel)?, &authenticator, &context, sequence + 1, unix_millis()?,
        )?;
        let gocode_api::RootHandleControlFrame::Result(result) = result else {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::InvalidContract));
        };
        if result.offer_digest() != ready.offer_digest() {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        if result.accepted() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.root_control_sequence = sequence + 2;
        Ok(false)
    }

    fn poison_root_transport(&mut self) {
        use std::net::Shutdown;
        let _ = self.channel.shutdown(Shutdown::Both);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(all(unix, feature = "protected-channel-integration"))]
struct RootHandleTransaction {
    authenticator: gocode_api::RootHandleTransferAuthenticator,
    context: gocode_api::RootHandleTransferContext,
    sequence: u64,
    offer: gocode_api::RootHandleTransferOffer,
}

#[cfg(not(all(unix, feature = "protected-channel-integration")))]
impl ProtectedBundledRuntimeProcess {
    /// Protected root-handle transport is unavailable without its native integration feature.
    ///
    /// # Errors
    ///
    /// Always returns a closed unsupported-platform failure.
    pub fn prepare_root_handle(
        &mut self,
        _root: &crate::VerifiedRootHandle,
        _workspace_id: gocode_domain::id::WorkspaceId,
        _expected_version: u64,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
    }
}
