use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::{CredentialEnrollmentStoreAuthority, EnrollmentAuthoritySeal};
use crate::{BeginCredentialOperation, CredentialEnrollmentError, CredentialOperationAction};

const DOMAIN: &[u8] = b"GOCODE_LEGACY_IMPORT_AUTHORIZATION_V1\0";

#[derive(Debug)]
pub struct CredentialLegacyImportAuthorization {
    seal: Arc<EnrollmentAuthoritySeal>,
    binding: [u8; 32],
}

impl PartialEq for CredentialLegacyImportAuthorization {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.seal, &other.seal) && self.binding == other.binding
    }
}

impl Eq for CredentialLegacyImportAuthorization {}

impl CredentialEnrollmentStoreAuthority {
    /// Seals exact protected daemon metadata for one legacy-import begin request.
    pub fn issue_legacy_import_authorization(
        &self,
        input: &BeginCredentialOperation,
    ) -> Result<CredentialLegacyImportAuthorization, CredentialEnrollmentError> {
        if input.action() != CredentialOperationAction::MigrateLegacy
            || input.qualified_release_tuple().is_none()
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(CredentialLegacyImportAuthorization {
            seal: self.seal.clone(),
            binding: binding(input),
        })
    }

    /// Confirms that a legacy-import request retains its store-paired sealed provenance.
    pub fn validate_legacy_import_authorization(
        &self,
        input: &BeginCredentialOperation,
        authorization: &CredentialLegacyImportAuthorization,
    ) -> Result<(), CredentialEnrollmentError> {
        (input.action() == CredentialOperationAction::MigrateLegacy
            && Arc::ptr_eq(&self.seal, &authorization.seal)
            && authorization.binding == binding(input))
        .then_some(())
        .ok_or(CredentialEnrollmentError::InvalidEvidence)
    }
}

fn binding(input: &BeginCredentialOperation) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(input.command_id().as_bytes());
    hash_len_prefixed(&mut hash, input.idempotency_key().as_str().as_bytes());
    hash.update(input.operation_id().as_bytes());
    hash.update(input.installation_owner_id().as_bytes());
    hash_len_prefixed(&mut hash, input.provider_id().as_str().as_bytes());
    hash.update(input.expected_lifecycle_revision().get().to_be_bytes());
    hash.update(input.expected_prior_fence().get().to_be_bytes());
    hash.update(input.begin_proof_digest().as_bytes());
    hash.update(input.begin_proof_expires_at_high_water().to_be_bytes());
    if let Some(version) = input.allocated_credential_version() {
        hash.update(version.version().to_be_bytes());
        hash.update(version.ref_digest());
    }
    hash.update(
        input
            .qualified_release_tuple()
            .expect("legacy authorization requires a tuple")
            .digest()
            .as_bytes(),
    );
    hash.finalize().into()
}

fn hash_len_prefixed(hash: &mut Sha256, value: &[u8]) {
    hash.update(
        u32::try_from(value.len())
            .expect("validated identifier length")
            .to_be_bytes(),
    );
    hash.update(value);
}
