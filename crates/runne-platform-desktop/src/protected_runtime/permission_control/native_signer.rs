impl ProtectedBundledRuntimeSupervisor {
    /// Consumes native warning and optional fresh PAM evidence for the active exchange.
    ///
    /// # Errors
    /// Returns an error if authenticated cancellation or consent exchange fails.
    pub fn complete_permission_mode_consent(
        &mut self,
        warning: crate::permission_reauth_linux::NativePermissionWarningConfirmationV1,
        os_reauthentication: Option<crate::permission_reauth_linux::FreshOsReauthentication>,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        self.complete_permission_mode_consent_with_consumer(
            warning,
            os_reauthentication,
            |token, challenge_digest| {
                crate::permission_reauth_linux::consume_verified(token, challenge_digest)
                    .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
            },
        )
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "The private helper receives the move-only native acknowledgement from its one-shot public entry point."
    )]
    fn complete_permission_mode_consent_with_consumer(
        &mut self,
        warning: crate::permission_reauth_linux::NativePermissionWarningConfirmationV1,
        os_reauthentication: Option<crate::permission_reauth_linux::FreshOsReauthentication>,
        consume_os: impl FnOnce(
            crate::permission_reauth_linux::FreshOsReauthentication,
            [u8; 32],
        ) -> Result<
            runne_linux_pam::VerifiedPamFacts,
            ProtectedBundledRuntimeError,
        >,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        let (exchange, _) = self.current_permission_mode_exchange()?;
        let consent = (|| {
            let confirmation_digest =
                crate::permission_reauth_linux::native_confirmation_binding_digest(
                    &exchange.context,
                    &exchange.challenge,
                )
                .map_err(|()| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            if !warning.matches_exchange(
                &exchange.context,
                &exchange.challenge,
                confirmation_digest,
                unix_millis()?,
            ) {
                return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
            }
            let os_attestation = match (exchange.challenge.requested_mode, os_reauthentication) {
                (runne_api::PermissionModeSelectionV1::FullAccess, Some(token)) => {
                    let facts =
                        consume_os(token, exchange.challenge.issued_challenge_binding_digest)?;
                    runne_api::ModeOsAttestationV1::Fresh {
                        qualified_fingerprint: facts.qualified_fingerprint(),
                        authenticated_at_unix_ms: facts.authenticated_at_unix_ms(),
                    }
                }
                (runne_api::PermissionModeSelectionV1::FullAccess, None) | (_, Some(_)) => {
                    return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
                }
                (_, None) => runne_api::ModeOsAttestationV1::NotRequired,
            };
            let mut consent = runne_api::PermissionControlModeConsentV1 {
                challenge_id: exchange.challenge.challenge_id,
                public_request_digest: exchange.context.public_request_digest,
                issued_challenge_binding_digest: exchange.challenge.issued_challenge_binding_digest,
                native_warning_version: exchange.challenge.native_warning_version,
                requested_mode: exchange.challenge.requested_mode,
                confirmed_binding_digest: confirmation_digest,
                warning_attestation: [0; 32],
                os_attestation,
            };
            let process = self
                .process
                .as_ref()
                .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
            consent.warning_attestation = process
                .keys
                .permission_control_native_authenticator()
                .authenticate_mode_consent(&exchange.context, &consent)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            Ok(consent)
        })();
        let Ok(consent) = consent else {
            return self.cancel_permission_mode();
        };
        self.finish_permission_mode_exchange(Payload::ModeConsent(consent))
    }

    /// Cancels the active authenticated permission-mode exchange.
    ///
    /// # Errors
    /// Returns an error if the daemon does not authenticate the cancellation result.
    pub fn cancel_permission_mode(
        &mut self,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        self.finish_permission_mode_exchange(Payload::Cancel)
    }

    fn finish_permission_mode_exchange(
        &mut self,
        payload: Payload,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        self.finish_exchange(payload)
    }

    fn current_permission_mode_exchange(
        &self,
    ) -> Result<(PermissionModeExchangeV1, u64), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let owner = self
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .permission_control_owner()?;
        let sequence = self
            .permission_control_sequence
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        if sequence.owner != owner {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        Ok((
            sequence
                .active
                .clone()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?,
            sequence.last_authenticated_sequence,
        ))
    }

    fn finish_exchange(
        &mut self,
        payload: Payload,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        let is_consent = matches!(&payload, Payload::ModeConsent(_));
        let mut response_started = false;
        let result = self.finish_exchange_attempt(payload, &mut response_started);
        if is_consent && result.is_err() && !response_started {
            let mut cancel_started = false;
            let cancellation = self.finish_exchange_attempt(Payload::Cancel, &mut cancel_started);
            if cancellation.is_err() && cancel_started {
                self.record_client_failure()?;
            }
            return cancellation;
        }
        if result.is_err() && response_started {
            self.record_client_failure()?;
        }
        result
    }

    fn finish_exchange_attempt(
        &mut self,
        payload: Payload,
        response_started: &mut bool,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        let (exchange, last_sequence) = self.current_permission_mode_exchange()?;
        let result = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .finish_permission_mode_exchange(&exchange, last_sequence, payload, response_started);
        match result {
            Ok((result, sequence_number)) => {
                if let Some(sequence) = self.permission_control_sequence.as_mut() {
                    sequence.last_authenticated_sequence = sequence_number;
                    sequence.active = None;
                }
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }
}

impl ProtectedBundledRuntimeProcess {
    fn finish_permission_mode_exchange(
        &mut self,
        exchange: &PermissionModeExchangeV1,
        previous_sequence: u64,
        payload: Payload,
        response_started: &mut bool,
    ) -> Result<(PermissionControlResultV1, u64), ProtectedBundledRuntimeError> {
        if self.permission_control_owner()? != exchange.owner {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        if matches!(payload, Payload::ModeConsent(ref consent)
            if consent.challenge_id != exchange.challenge.challenge_id
                || consent.public_request_digest != exchange.context.public_request_digest
                || consent.issued_challenge_binding_digest
                    != exchange.challenge.issued_challenge_binding_digest
                || consent.requested_mode != exchange.challenge.requested_mode
                || consent.native_warning_version != exchange.challenge.native_warning_version)
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let authenticator = PermissionControlAuthenticatorV1::from_protected_activation(
            &self.keys,
            Purpose::ModeControl,
        );
        let next = previous_sequence
            .checked_add(1)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let request = Zeroizing::new(
            authenticator
                .issue_frame(
                    exchange.context.clone(),
                    next,
                    Direction::DesktopToDaemon,
                    payload,
                )
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?,
        );
        let mut result_context = exchange.context.clone();
        result_context.predecessor_transcript_digest = Sha256::digest(&request[..]).into();
        let wire_request = permission_wire_outer_frame(&request)?;
        *response_started = true;
        write_frame(&mut self.channel, &wire_request)?;
        let wire_response = Zeroizing::new(read_frame(&mut self.channel)?);
        let response = permission_wire_inner_frame(&wire_response)?;
        let authenticated = authenticator
            .authenticate_frame(
                &response,
                &result_context,
                Purpose::ModeControl,
                Phase::Result,
                Direction::DaemonToDesktop,
                previous_sequence,
                unix_millis()?,
            )
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let Payload::Result(result) = authenticated.payload() else {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        };
        if result.command_id != exchange.context.command_id
            || result.public_request_digest != exchange.context.public_request_digest
            || (result.code == PermissionControlResultCodeV1::Committed
                && (result.receipt_digest.is_none()
                    || result.authorization_revision.is_none()
                    || result.managed_policy_revision.is_none()))
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        Ok((result.clone(), authenticated.sequence()))
    }
}
