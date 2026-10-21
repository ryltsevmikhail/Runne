use super::{MetadataQueryError, json_envelope, map_only::MapOnly, storage::SnapshotWire};
use serde::Deserialize;
#[derive(Deserialize)]
struct HeaderWire {
    schema_version: u16,
}
pub(super) fn parse(bytes: &[u8]) -> Result<SnapshotWire, MetadataQueryError> {
    json_envelope::check(bytes)?;
    let header: MapOnly<HeaderWire> = full_parse(bytes)?;
    if header.0.schema_version != 1 {
        return Err(MetadataQueryError::UnsupportedContract);
    }
    let snapshot: MapOnly<SnapshotWire> = full_parse(bytes)?;
    Ok(snapshot.0)
}
fn full_parse<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, MetadataQueryError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut de).map_err(|_| MetadataQueryError::InvalidSnapshot)?;
    de.end().map_err(|_| MetadataQueryError::InvalidSnapshot)?;
    Ok(value)
}
