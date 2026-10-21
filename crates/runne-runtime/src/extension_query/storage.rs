use super::map_only::MapOnly;
use super::storage_record::RecordWire;
use super::*;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotWire {
    pub(super) schema_version: u16,
    pub(super) authority_id: String,
    pub(super) principal_id: String,
    pub(super) project_id: String,
    pub(super) registration_revision: u64,
    pub(super) registrations: Vec<MapOnly<RecordWire>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileWire {
    pub(super) id: String,
    pub(super) revision: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackageWire {
    pub(super) version: String,
    pub(super) digest: String,
}
impl SnapshotWire {
    pub(super) fn normalize(self) -> Result<Vec<ConfiguredMetadata>, MetadataQueryError> {
        let invalid = MetadataQueryError::InvalidSnapshot;
        if self.schema_version != 1
            || !bounded_revision(self.registration_revision)
            || !valid_uuid(&decode_hex(&self.authority_id)?)
            || !valid_uuid(&decode_hex(&self.project_id)?)
            || runne_api::ApiPrincipalId::new(&self.principal_id).is_err()
        {
            return Err(invalid);
        }
        if self.registrations.len() > 256 {
            return Err(MetadataQueryError::LimitExceeded);
        }
        let mut records = self
            .registrations
            .into_iter()
            .map(|r| r.0.normalize())
            .collect::<Result<Vec<_>, _>>()?;
        records.sort_by_key(|r| r.key());
        if records.windows(2).any(|r| r[0].key() == r[1].key()) {
            return Err(invalid);
        }
        Ok(records)
    }
}
