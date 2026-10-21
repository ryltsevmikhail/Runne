use super::*;
use std::fs::File;
pub(super) struct Source(pub(super) File);
identity::opaque!(Source);
pub(super) fn capture(
    file: File,
    expected: RegistryExpectation,
) -> Result<ConfiguredExtensionRegistry, MetadataQueryError> {
    expected.validate()?;
    let source = Source(file);
    #[cfg(not(unix))]
    {
        let _ = source;
        Err(MetadataQueryError::SourceUnavailable)
    }
    #[cfg(unix)]
    {
        inspect_file(&source.0)?;
        let bytes = bounded_capture::read_from_start(&source.0)?;
        publish(&bytes, expected)
    }
}
pub(super) fn inspect_file(file: &File) -> Result<(), MetadataQueryError> {
    let metadata = file
        .metadata()
        .map_err(|_| MetadataQueryError::SourceUnavailable)?;
    if !metadata.is_file() {
        return Err(MetadataQueryError::InvalidSnapshot);
    }
    if metadata.len() > bounded_capture::MAX_INPUT_BYTES as u64 {
        return Err(MetadataQueryError::LimitExceeded);
    }
    Ok(())
}
pub(super) fn publish(
    bytes: &[u8],
    expected: RegistryExpectation,
) -> Result<ConfiguredExtensionRegistry, MetadataQueryError> {
    expected.validate()?;
    if bytes.len() > bounded_capture::MAX_INPUT_BYTES {
        return Err(MetadataQueryError::LimitExceeded);
    }
    let wire = storage_header::parse(bytes)?;
    let invalid = MetadataQueryError::InvalidSnapshot;
    let matches = decode_hex::<16>(&wire.authority_id)? == expected.scope.authority_id
        && wire.principal_id == expected.scope.principal.as_str()
        && decode_hex::<16>(&wire.project_id)? == *expected.scope.project.as_bytes()
        && wire.registration_revision == expected.version.registration_revision;
    let records = wire.normalize()?;
    if !matches
        || digest::metadata_digest(
            &expected.scope,
            expected.version.registration_revision,
            &records,
        ) != expected.version.metadata_digest
    {
        return Err(invalid);
    }
    Ok(ConfiguredExtensionRegistry::new(expected, records))
}
