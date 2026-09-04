use runne_provider::{CredentialBindingDigest, CredentialBrokerCommand, CredentialVersionRef};
use sha2::{Digest, Sha256};

use super::errors::BrokerError;
use super::readback::CredentialReadbackObservation;
use crate::SecureStoreError;

const READBACK_DOMAIN: &[u8] = b"runne/provider-credential-readback/v1\0";
const VERSION_TARGET: u8 = 1;
const EXACT_LEGACY_SOURCE_TARGET: u8 = 5;

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
    let runne_provider::CredentialBrokerTarget::ExactLegacySource(binding) = command.target()
    else {
        return Err(BrokerError::AccessDenied.into());
    };
    let mut digest = base_digest(command, false);
    digest.update([EXACT_LEGACY_SOURCE_TARGET]);
    digest.update(binding.import_operation_id().as_bytes());
    digest.update(binding.import_lifecycle_revision().get().to_be_bytes());
    digest.update(binding.import_fence().get().to_be_bytes());
    digest.update(binding.destination().provider().as_str().as_bytes());
    digest.update(binding.destination().version().to_be_bytes());
    digest.update(binding.destination().ref_digest());
    digest.update(binding.observation_digest().as_bytes());
    finish(digest, false)
}

pub(super) fn legacy_import_observation(
    command: &CredentialBrokerCommand,
    reference: &CredentialVersionRef,
    source_revision: crate::ProviderCredentialSourceRevision,
) -> Result<CredentialReadbackObservation, SecureStoreError> {
    if command.target().version_ref() != Some(reference) {
        return Err(BrokerError::Corrupt.into());
    }
    let binding = command
        .legacy_source_observation_digest(*source_revision.as_bytes())
        .map_err(|_| BrokerError::Corrupt)?;
    Ok(CredentialReadbackObservation {
        binding,
        present: true,
    })
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
