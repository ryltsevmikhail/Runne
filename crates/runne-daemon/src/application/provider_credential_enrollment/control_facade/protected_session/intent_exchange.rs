use super::*;
use runne_api::{ApiActor, ApiPrincipalId, ProviderCredentialCommandContext};
use runne_domain::id::{CommandId, IdempotencyKey};

impl DaemonProtectedCredentialEnrollmentSession {
    /// Authenticates one exact native request and returns its daemon admission proof.
    pub(crate) fn accept_request(
        &mut self,
        frame: &[u8],
        now_unix_millis: u64,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        if self.pending.is_some() || self.begun.is_some() || self.recovery.started {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let request = self
            .authenticator
            .decode_authenticated_request(frame, 0, now_unix_millis)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.require_request(&request)?;
        let binding = self.admission_binding(&request)?;
        let admission = self
            .authenticator
            .issue_admission(&request, binding.clone(), request.sequence() + 1)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let encoded =
            ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
        let verified = self
            .authenticator
            .decode_admission(
                &encoded,
                &request,
                &binding,
                request.sequence(),
                now_unix_millis,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.pending = Some(VerifiedAdmission {
            request,
            admission: verified,
        });
        Ok(encoded)
    }

    /// Consumes a verified admission and returns only the safe operation projection.
    pub(crate) fn begin(
        &mut self,
        frame: &[u8],
        now_unix_millis: u64,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        if self.recovery.started {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let command = self
            .lifecycle
            .decode_desktop_begin(frame, self.desktop_sequence)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.desktop_sequence = self
            .desktop_sequence
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if let Some((prior, snapshot)) = &self.begun {
            if prior != &command {
                return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
            }
            return self.encode_snapshot(snapshot.clone());
        }
        let pending = self
            .pending
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let context = command_context(&command)?;
        self.admissions
            .register(pending.request, pending.admission, context, now_unix_millis)?;
        let (authority, proof, context, broker_transfer) = self
            .admissions
            .resolve_begin_with_broker_transfer(&command, self.facts.session, now_unix_millis)?;
        let rendezvous = self
            .rendezvous
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.control
            .rendezvous
            .reserve_transition_rendezvous_with_transfer(
                rendezvous,
                &authority,
                &proof,
                broker_transfer,
            )?;
        let now_high_water = i64::try_from(now_unix_millis / 1_000)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let snapshot = self.control.begin_admitted(
            self.verifier.clone(),
            &authority,
            &proof,
            &context,
            &command,
            now_high_water,
        )?;
        let operation_id = self.control.handles.resolve(snapshot.operation_handle())?;
        let operation = runne_provider::ProviderCredentialEnrollmentStore::load_operation(
            self.control.store.as_ref(),
            operation_id,
        )
        .map_err(crate::application::provider_credential_enrollment::effect_authority::map_store)?;
        if let Some(rendezvous_id) = snapshot.broker_rendezvous_id() {
            self.handoff = Some(self.control.rendezvous.begin_endpoint_handoff(
                rendezvous_id,
                &operation,
                &authority,
                &proof,
                now_high_water,
            )?);
        } else if snapshot.state().terminal() {
            self.control
                .rendezvous
                .discard_transition_rendezvous(&authority, &proof)?;
        } else {
            return Err(ProviderCredentialEnrollmentHostError::InvariantViolation);
        }
        self.begun = Some((command, snapshot.clone()));
        self.encode_snapshot(snapshot)
    }
}

fn command_context(
    command: &BeginProviderCredentialEnrollment,
) -> Result<ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError> {
    Ok(ProviderCredentialCommandContext {
        command_id: CommandId::parse(command.command_identity())
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
        idempotency_key: IdempotencyKey::new(command.idempotency_key())
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
        principal: ApiPrincipalId::new("protected-desktop-owner")
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        actor: ApiActor::new("runne-tauri-native-host")
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
    })
}
