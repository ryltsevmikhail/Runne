//! Internal trust-lineage binding for opaque receipt handles.

use crate::{
    AuthorityError, ProjectOwnerTrustConfigV1, ProjectOwnerTrustConfigV2, ProjectOwnerTrustConfigV3,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTrustLineage {
    config_sha256: [u8; 32],
    key_id: [u8; 32],
    epoch: u64,
    schema_version: String,
}

impl VerifiedTrustLineage {
    pub(crate) fn v1(value: &ProjectOwnerTrustConfigV1) -> Result<Self, AuthorityError> {
        Ok(Self {
            config_sha256: value.sha256()?,
            key_id: value.key_id,
            epoch: value.epoch,
            schema_version: value.schema_version.clone(),
        })
    }

    pub(crate) fn v2(value: &ProjectOwnerTrustConfigV2) -> Result<Self, AuthorityError> {
        Ok(Self {
            config_sha256: value.sha256()?,
            key_id: value.key_id,
            epoch: value.epoch,
            schema_version: value.schema_version.clone(),
        })
    }

    pub(crate) fn authorizes_v2(
        &self,
        trust: &ProjectOwnerTrustConfigV2,
    ) -> Result<(), AuthorityError> {
        self.authorizes(
            trust.predecessor,
            &trust.predecessor_schema_version,
            trust.key_id,
            trust.epoch,
        )
    }

    pub(crate) fn authorizes_v3(
        &self,
        trust: &ProjectOwnerTrustConfigV3,
    ) -> Result<(), AuthorityError> {
        self.authorizes(
            trust.predecessor,
            &trust.predecessor_schema_version,
            trust.key_id,
            trust.epoch,
        )
    }

    fn authorizes(
        &self,
        predecessor: [u8; 32],
        predecessor_schema: &str,
        key_id: [u8; 32],
        epoch: u64,
    ) -> Result<(), AuthorityError> {
        if predecessor != self.config_sha256
            || predecessor_schema != self.schema_version
            || key_id == self.key_id
            || epoch
                != self
                    .epoch
                    .checked_add(1)
                    .ok_or(AuthorityError::InvalidReceiptTrust)?
        {
            return Err(AuthorityError::InvalidReceiptTrust);
        }
        Ok(())
    }
}
