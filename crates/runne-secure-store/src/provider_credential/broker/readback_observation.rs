use runne_provider::{CredentialBindingDigest, CredentialBrokerCommand, CredentialVersionRef};
use sha2::{Digest, Sha256};

use super::errors::BrokerError;
use super::readback::CredentialReadbackObservation;
use crate::SecureStoreError;

const READBACK_DOMAIN: &[u8] = b"runne/provider-credential-readback/v1\0";
const VERSION_TARGET: u8 = 1;
const LEGACY_SOURCE_TARGET: u8 = 2;

pub(super) fn version_observation(
    command: &CredentialBrokerCommand,
    reference: &CredentialVersionRef,
    present: bool,
) -> Result<CredentialReadbackObservation, SecureStoreError> {
    let mut digest = base_digest(command, present);
    digest.update([VERSION_TARGET]);
    digest.update(reference.provider().as_str().as_bytes());
    digest.update(reference.version().to_be_bytes());
    digest.update(reference.ref_digest());
    finish(digest, present)
}

pub(super) fn legacy_observation(
    command: &CredentialBrokerCommand,
) -> Result<CredentialReadbackObservation, SecureStoreError> {
    let mut digest = base_digest(command, false);
    digest.update([LEGACY_SOURCE_TARGET]);
    finish(digest, false)
}

fn base_digest(command: &CredentialBrokerCommand, present: bool) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(READBACK_DOMAIN);
    digest.update(command.operation_id().as_bytes());
    digest.update(command.provider().as_str().as_bytes());
    digest.update([command.action() as u8, u8::from(present)]);
    digest.update(command.expected_lifecycle_revision().get().to_be_bytes());
    digest.update(command.expected_prior_fence().get().to_be_bytes());
    digest
}

fn finish(
    digest: Sha256,
    present: bool,
) -> Result<CredentialReadbackObservation, SecureStoreError> {
    Ok(CredentialReadbackObservation {
        binding: CredentialBindingDigest::from_measured(digest.finalize().into())
            .map_err(|_| BrokerError::Corrupt)?,
        present,
    })
}
