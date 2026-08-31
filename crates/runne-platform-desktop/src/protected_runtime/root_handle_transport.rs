#[cfg(all(any(unix, windows), feature = "protected-channel-integration"))]
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
        workspace_id: runne_api::WorkspaceId,
        expected_version: u64,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.prepare_root_admission(root, workspace_id, expected_version)
            .map(|_| ())
    }

    /// Transfers one verified root and returns only the signed opaque admission.
    ///
    /// Paths, descriptor values, and transfer references remain native-host-only.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the protected channel, transfer, or daemon
    /// admission authority rejects the exact root context.
    pub fn prepare_root_admission(
        &mut self,
        root: &crate::VerifiedRootHandle,
        workspace_id: runne_api::WorkspaceId,
        expected_version: u64,
    ) -> Result<runne_api::ProtectedRootHandleAdmission, ProtectedBundledRuntimeError> {
        let transaction = self.root_handle_preflight(workspace_id, expected_version)?;
        match self.prepare_root_handle_transaction(root, transaction) {
            Ok(Some(admission)) => Ok(admission),
            Ok(None) => Err(ProtectedBundledRuntimeError::OwnershipMismatch),
            Err(error) => { self.poison_root_transport(); Err(error) }
        }
    }

    fn root_handle_preflight(
        &self,
        workspace_id: runne_api::WorkspaceId,
        expected_version: u64,
    ) -> Result<RootHandleTransaction, ProtectedBundledRuntimeError> {
        if self.graceful_requested { return Err(ProtectedBundledRuntimeError::InvalidState); }
        let receiver_pid = self.child.id();
        let sender_pid = std::process::id();
        #[cfg(unix)]
        let effective_uid = rustix::process::geteuid().as_raw();
        #[cfg(windows)]
        let effective_uid = 0;
        let now = unix_millis()?;
        let expires = now.checked_add(30_000).ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let owned = self
            .activation
            .compatibility_owned()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let context = runne_api::RootHandleTransferContext::new(
            *owned.launch_authority_id(),
            *owned.session_id(),
            owned.launch_generation(), sender_pid, receiver_pid,
            effective_uid, workspace_id, expected_version, *uuid::Uuid::now_v7().as_bytes(), now, expires,
        )?;
        let authenticator = runne_api::RootHandleTransferAuthenticator::from_protected_activation(&self.keys);
        let sequence = self.root_control_sequence.checked_add(1)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let offer = runne_api::RootHandleTransferOffer::new(context.clone(), sequence, &authenticator)?;
        Ok(RootHandleTransaction { authenticator, context, sequence, offer })
    }

    fn prepare_root_handle_transaction(
        &mut self,
        root: &crate::VerifiedRootHandle,
        transaction: RootHandleTransaction,
    ) -> Result<Option<runne_api::ProtectedRootHandleAdmission>, ProtectedBundledRuntimeError> {
        let RootHandleTransaction { authenticator, context, sequence, offer } = transaction;
        let offer_digest = offer.digest();
        write_frame(
            &mut self.channel,
            &runne_api::RootHandleControlFrame::Offer(offer).encode_frame(),
        )?;
        let ready = runne_api::RootHandleControlFrame::decode_and_verify(
            &read_frame(&mut self.channel)?, &authenticator, &context, sequence, unix_millis()?,
        )?;
        let runne_api::VerifiedRootHandleControlFrame::Ready(ready) = ready else {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::InvalidContract));
        };
        if ready.offer_digest() != &offer_digest {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        #[cfg(unix)]
        let mut endpoint = crate::ProtectedRootHandleEndpoint::from_owned_protected_channel(
            self.channel
                .try_clone()
                .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?,
            authenticator.clone(),
            &context,
            *ready.offer_digest(),
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        #[cfg(windows)]
        let mut endpoint = crate::ProtectedRootHandleEndpoint::from_parent_protected_channel(
            self.channel
                .try_clone()
                .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?,
            &self.child,
            &context,
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        endpoint.send(root).map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        endpoint.finish().map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let result = runne_api::RootHandleControlFrame::decode_and_verify(
            &read_frame(&mut self.channel)?, &authenticator, &context, sequence + 1, unix_millis()?,
        )?;
        let runne_api::VerifiedRootHandleControlFrame::Result(result) = result else {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::InvalidContract));
        };
        let accepted = result.accepted();
        let admission = result.into_protected_admission();
        if !accepted || admission.is_none() {
            self.root_control_sequence = sequence + 2;
            return Ok(None);
        }
        self.root_control_sequence = sequence + 2;
        Ok(admission)
    }

    fn poison_root_transport(&mut self) {
        #[cfg(unix)]
        use std::net::Shutdown;
        #[cfg(unix)]
        let _ = self.channel.shutdown(Shutdown::Both);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(all(any(unix, windows), feature = "protected-channel-integration"))]
struct RootHandleTransaction {
    authenticator: runne_api::RootHandleTransferAuthenticator,
    context: runne_api::RootHandleTransferContext,
    sequence: u64,
    offer: runne_api::RootHandleTransferOffer,
}

#[cfg(not(all(any(unix, windows), feature = "protected-channel-integration")))]
impl ProtectedBundledRuntimeProcess {
    /// Protected root-handle transport is unavailable without its native integration feature.
    ///
    /// # Errors
    ///
    /// Always returns a closed unsupported-platform failure.
    pub const fn prepare_root_handle(
        &mut self,
        _root: &crate::VerifiedRootHandle,
        _workspace_id: runne_api::WorkspaceId,
        _expected_version: u64,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
    }

    /// Protected root admission is unavailable without native channel support.
    ///
    /// # Errors
    ///
    /// Always returns an unsupported-platform failure.
    pub const fn prepare_root_admission(
        &mut self,
        _root: &crate::VerifiedRootHandle,
        _workspace_id: runne_api::WorkspaceId,
        _expected_version: u64,
    ) -> Result<runne_api::ProtectedRootHandleAdmission, ProtectedBundledRuntimeError> {
        Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
    }
}
