//! Public-binding and resource validation for encrypted owner-key backups.

use crate::{
    AuthorityError, BackupMetadataV1, ProjectOwnerTrustConfigV1, backup::key_fingerprint, key_id,
};

pub fn validate_trust(trust: &ProjectOwnerTrustConfigV1) -> Result<(), AuthorityError> {
    if trust.repository_id != "runne"
        || trust.role != "PROJECT_OWNER"
        || trust.key_id != key_id(&trust.public_key)
        || trust.epoch == 0
    {
        return Err(AuthorityError::InvalidBackupBinding);
    }
    Ok(())
}

pub fn validate_expected_binding(
    metadata: &BackupMetadataV1,
    trust: &ProjectOwnerTrustConfigV1,
) -> Result<(), AuthorityError> {
    validate_trust(trust)?;
    let matches_repository = metadata.repository_id == trust.repository_id;
    let matches_key_id = metadata.key_id == trust.key_id;
    let matches_epoch = metadata.key_epoch == trust.epoch;
    let matches_fingerprint = metadata.key_fingerprint == key_fingerprint(&trust.public_key);
    if !(matches_repository && matches_key_id && matches_epoch && matches_fingerprint) {
        return Err(AuthorityError::InvalidBackupBinding);
    }
    Ok(())
}

pub fn validate_metadata(metadata: &BackupMetadataV1) -> Result<(), AuthorityError> {
    metadata.parameters.validate()?;
    if metadata.repository_id != "runne"
        || metadata.key_epoch == 0
        || !(16..=64).contains(&metadata.salt.len())
        || metadata.ciphertext.len() != 48
    {
        return Err(AuthorityError::InvalidBackupMetadata);
    }
    Ok(())
}
