use std::time::{Duration, Instant};

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceCancellation, CredentialServicePortError,
    CredentialServiceRuntimePort, CredentialServiceRuntimeRequest,
};
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialMutationGrant,
    CredentialRuntimeArmAuthority, CredentialRuntimeMutationPlan, CredentialServiceCorrelation,
    CredentialServiceDeadline, CredentialServiceDisposition, CredentialServiceEpoch,
    CredentialServiceProtocolCodec, CredentialServiceReply, CredentialServiceRequest,
    CredentialServiceRequestSequence, CredentialWriterBrokerHandoffFrame,
};

use super::CredentialServiceRuntimeSession;

mod read;
#[cfg(test)]
mod tests;

impl CredentialServiceRuntimeSession {
    pub(crate) fn arm_mutation(
        &mut self,
        runtime: &tokio::runtime::Handle,
        authority: &CredentialRuntimeArmAuthority,
        command: CredentialBrokerCommand,
        now_unix_millis: u64,
    ) -> Result<CredentialWriterBrokerHandoffFrame, ProviderCredentialEnrollmentHostError> {
        let client = self
            .client
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::Unsupported)?;
        let result = runtime.block_on(self.arm_mutation_with_port(
            &client,
            authority,
            command,
            now_unix_millis,
        ));
        self.client = Some(client);
        if self.last_transport_failure {
            self.queue_transport_rejoin()?;
        }
        result
    }

    pub(in crate::protected_activation) async fn arm_mutation_with_port<
        P: CredentialServiceRuntimePort,
    >(
        &mut self,
        port: &P,
        authority: &CredentialRuntimeArmAuthority,
        command: CredentialBrokerCommand,
        now_unix_millis: u64,
    ) -> Result<CredentialWriterBrokerHandoffFrame, ProviderCredentialEnrollmentHostError> {
        let sequence = self.next_sequence()?;
        let expires_at = self.expires_at(now_unix_millis)?;
        let deadline = CredentialServiceDeadline::new(now_unix_millis, expires_at)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let grant = CredentialMutationGrant::generate().map_err(|error| match error {
            runne_provider::CredentialEnrollmentError::EntropyUnavailable => {
                ProviderCredentialEnrollmentHostError::Unavailable
            }
            _ => ProviderCredentialEnrollmentHostError::InvariantViolation,
        })?;
        let plan = CredentialRuntimeMutationPlan::issue(
            authority,
            command,
            CredentialServiceEpoch::from_bytes(*self.binding.service_epoch())
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
            *self.binding.installation_owner(),
            *self.binding.protected_session_id(),
            self.binding.runtime_generation(),
            CredentialBindingDigest::from_measured(*self.binding.release_binding())
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
            CredentialServiceRequestSequence::new(sequence)
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
            CredentialServiceCorrelation::from_bytes(*uuid::Uuid::now_v7().as_bytes())
                .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?,
            deadline,
            grant.digest(),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        let (arm, writer_handoff) = plan.split();
        let reply = self
            .exchange(
                port,
                CredentialServiceRequest::RuntimeMutationArm(arm),
                expires_at - now_unix_millis,
                RuntimeCall::Arm,
            )
            .await?;
        match reply {
            CredentialServiceReply::Armed => {
                CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer_handoff, grant)
                    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
            }
            CredentialServiceReply::Rejected(disposition) => Err(self.map_disposition(disposition)),
            _ => Err(ProviderCredentialEnrollmentHostError::AccessDenied),
        }
    }

    fn next_sequence(&mut self) -> Result<u64, ProviderCredentialEnrollmentHostError> {
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        self.next_sequence = sequence;
        Ok(sequence)
    }

    fn expires_at(&self, now: u64) -> Result<u64, ProviderCredentialEnrollmentHostError> {
        now.checked_add(CredentialServiceDeadline::MAX_LIFETIME_MILLIS)
            .ok_or(ProviderCredentialEnrollmentHostError::InvalidRequest)
            .map(|expiry| expiry.min(self.binding.expires_at_unix_millis()))
    }

    async fn exchange<P: CredentialServiceRuntimePort>(
        &mut self,
        port: &P,
        request: CredentialServiceRequest,
        lifetime_millis: u64,
        call: RuntimeCall,
    ) -> Result<CredentialServiceReply, ProviderCredentialEnrollmentHostError> {
        let reply_context = request.context();
        let frame = CredentialServiceProtocolCodec::encode_request(request)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?
            .into_transport_bytes();
        let owner = *self.binding.installation_owner();
        let envelope = self
            .authenticator
            .authenticate_runtime_request(owner, &frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        let request =
            CredentialServiceRuntimeRequest::from_zeroizing(envelope.into_transport_bytes())
                .map_err(map_port_error)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(lifetime_millis))
            .ok_or(ProviderCredentialEnrollmentHostError::InvalidRequest)?;
        let context =
            CredentialServiceCallContext::new(deadline, CredentialServiceCancellation::new());
        self.last_transport_failure = false;
        let reply = match call {
            RuntimeCall::Arm => port.arm_mutation(request, context).await,
            RuntimeCall::Metadata => port.read_metadata(request, context).await,
            RuntimeCall::Material => port.read_material(request, context).await,
        };
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                self.last_transport_failure = is_transport_failure(error);
                return Err(map_port_error(error));
            }
        };
        let verified = reply
            .with_bytes(|bytes| self.authenticator.verify_runtime_reply(owner, bytes))
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let mut decoded = None;
        verified.consume(|bytes| {
            decoded = Some(CredentialServiceProtocolCodec::decode_runtime_reply(
                bytes,
                reply_context,
            ));
        });
        decoded
            .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    pub(super) fn map_disposition(
        &mut self,
        value: CredentialServiceDisposition,
    ) -> ProviderCredentialEnrollmentHostError {
        if let CredentialServiceDisposition::SessionMissing { current_epoch } = value {
            self.missing_epoch = Some(current_epoch);
        }
        map_disposition(value)
    }
}

const fn is_transport_failure(error: CredentialServicePortError) -> bool {
    matches!(
        error,
        CredentialServicePortError::Unavailable
            | CredentialServicePortError::TimedOut
            | CredentialServicePortError::Cancelled
            | CredentialServicePortError::Interrupted
            | CredentialServicePortError::Invalidated
            | CredentialServicePortError::OutcomeUnknown
    )
}

#[derive(Clone, Copy)]
enum RuntimeCall {
    Arm,
    Metadata,
    Material,
}

fn map_port_error(error: CredentialServicePortError) -> ProviderCredentialEnrollmentHostError {
    match error {
        CredentialServicePortError::Unsupported => {
            ProviderCredentialEnrollmentHostError::Unsupported
        }
        CredentialServicePortError::Rejected | CredentialServicePortError::InvalidReply => {
            ProviderCredentialEnrollmentHostError::AccessDenied
        }
        _ => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}

fn map_disposition(value: CredentialServiceDisposition) -> ProviderCredentialEnrollmentHostError {
    match value {
        CredentialServiceDisposition::Denied => ProviderCredentialEnrollmentHostError::AccessDenied,
        CredentialServiceDisposition::Unsupported => {
            ProviderCredentialEnrollmentHostError::Unsupported
        }
        _ => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}
