use super::super::{
    CredentialRuntimeReadBinding, CredentialServiceDeadline, CredentialServiceRequestSequence,
};
use super::support::{number, take, take_digest, take_epoch, take_vec};
use super::{digest, epoch, put_bytes};
use crate::credential::enrollment::{
    CredentialEnrollmentError, CredentialFence, CredentialLifecycleRevision,
};
use crate::{CredentialVersionRef, ProviderId};

pub(super) fn read_binding(
    out: &mut Vec<u8>,
    value: &CredentialRuntimeReadBinding,
) -> Result<(), CredentialEnrollmentError> {
    epoch(out, value.epoch());
    out.extend_from_slice(&value.session());
    out.extend_from_slice(&value.runtime_generation().to_be_bytes());
    digest(out, value.release_binding());
    put_bytes(out, value.provider().as_str().as_bytes())?;
    out.extend_from_slice(&value.version().version().to_be_bytes());
    out.extend_from_slice(&value.lifecycle_revision().get().to_be_bytes());
    out.extend_from_slice(&value.fence().get().to_be_bytes());
    out.extend_from_slice(&value.sequence().get().to_be_bytes());
    out.extend_from_slice(&value.correlation().as_bytes());
    out.extend_from_slice(&value.deadline().issued_at_unix_millis().to_be_bytes());
    out.extend_from_slice(&value.deadline().expires_at_unix_millis().to_be_bytes());
    Ok(())
}

pub(super) fn take_read_binding(
    bytes: &[u8],
    at: &mut usize,
) -> Result<CredentialRuntimeReadBinding, CredentialEnrollmentError> {
    let epoch = take_epoch(bytes, at)?;
    let session = take(bytes, at)?;
    let generation = number(bytes, at)?;
    let release = take_digest(bytes, at)?;
    let provider_text = String::from_utf8(take_vec(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let provider =
        ProviderId::new(provider_text).map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let version = CredentialVersionRef::new(provider.clone(), number(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let revision = CredentialLifecycleRevision::new(number(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let fence = CredentialFence::new(number(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let sequence = CredentialServiceRequestSequence::new(number(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let correlation = super::super::CredentialServiceCorrelation::from_bytes(take(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let deadline = CredentialServiceDeadline::new(number(bytes, at)?, number(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    CredentialRuntimeReadBinding::from_wire(
        epoch,
        session,
        generation,
        release,
        provider,
        version,
        revision,
        fence,
        sequence,
        correlation,
        deadline,
    )
    .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}
