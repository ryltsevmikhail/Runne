impl CutoverManifestFields {
    fn source_high_water(&self) -> u64 {
        self.migration_report.source_high_water
    }
}

fn validate_reference(reference: &str) -> Result<(), MigrationError> {
    if !valid_bounded(reference, MAX_ARTIFACT_REF_BYTES) {
        return Err(MigrationError::StorageContractViolation);
    }
    Ok(())
}

fn valid_bounded(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

fn all_artifacts_unique<'a>(artifacts: impl IntoIterator<Item = &'a ArtifactRef>) -> bool {
    let mut references = BTreeSet::new();
    artifacts
        .into_iter()
        .all(|artifact| artifact.is_valid() && references.insert(artifact.reference.as_str()))
}
