use crate::credential::enrollment::{CredentialBrokerCommandCodec, CredentialEnrollmentError};

use super::super::{
    CredentialMutationGrantDigest, CredentialServiceCorrelation, CredentialServiceDeadline,
    CredentialServiceRequestSequence,
};
use super::support::{number, take, take_digest, take_epoch, take_vec};
use super::{CredentialRuntimeMutationBinding, digest, put_bytes};

pub(super) fn mutation_binding(
    out: &mut Vec<u8>,
    value: &CredentialRuntimeMutationBinding,
) -> Result<(), CredentialEnrollmentError> {
    super::epoch(out, value.epoch);
    out.extend_from_slice(&value.installation_owner);
    out.extend_from_slice(&value.session);
    out.extend_from_slice(&value.runtime_generation.to_be_bytes());
    digest(out, value.release_binding);
    out.extend_from_slice(&value.sequence.get().to_be_bytes());
    out.extend_from_slice(&value.correlation.as_bytes());
    out.extend_from_slice(&value.deadline.issued_at_unix_millis().to_be_bytes());
    out.extend_from_slice(&value.deadline.expires_at_unix_millis().to_be_bytes());
    digest(out, value.grant_digest.binding_digest());
    let command = CredentialBrokerCommandCodec::encode(&value.command)?;
    put_bytes(out, &command)
}

pub(super) fn take_mutation_binding(
    bytes: &[u8],
    at: &mut usize,
) -> Result<CredentialRuntimeMutationBinding, CredentialEnrollmentError> {
    let epoch = take_epoch(bytes, at)?;
    let installation_owner = take(bytes, at)?;
    let session = take(bytes, at)?;
    let generation = number(bytes, at)?;
    let release = take_digest(bytes, at)?;
    let sequence = CredentialServiceRequestSequence::new(number(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let correlation = CredentialServiceCorrelation::from_bytes(take(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let deadline = CredentialServiceDeadline::new(number(bytes, at)?, number(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let grant = CredentialMutationGrantDigest::from_measurement(take_digest(bytes, at)?);
    let command = CredentialBrokerCommandCodec::decode(&take_vec(bytes, at)?)?;
    CredentialRuntimeMutationBinding::new(
        command,
        epoch,
        installation_owner,
        session,
        generation,
        release,
        sequence,
        correlation,
        deadline,
        grant,
    )
    .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}
