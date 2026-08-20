use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryFixtureManifest {
    pub(crate) manifest_version: u32,
    pub(crate) fixtures: Vec<RecoveryFixtureEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryFixtureEntry {
    pub(crate) path: String,
    pub(crate) fixture_kind: FixtureKind,
    pub(crate) source_commit: String,
    pub(crate) source_ref: String,
    pub(crate) writer_file: String,
    pub(crate) writer_symbol: String,
    pub(crate) writer_snapshot: String,
    pub(crate) writer_snapshot_sha256: String,
    pub(crate) writer_test: String,
    pub(crate) schema_version: i64,
    pub(crate) integrity_profile: u16,
    pub(crate) digest_domain: String,
    pub(crate) expected_rows: Vec<ExpectedFixtureRow>,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FixtureKind {
    HistoricalExtracted,
    SyntheticTestVector,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedFixtureRow {
    pub(crate) table: String,
    pub(crate) primary_key_hex: String,
    pub(crate) columns: BTreeMap<String, String>,
}

pub(crate) fn load_manifest_and_copy_fixture(
    entry_name: &str,
    destination: impl AsRef<Path>,
) -> Result<RecoveryFixtureEntry, String> {
    let destination = destination.as_ref();
    let fixture_root = validate_destination(destination)?;
    let manifest = load_manifest()?;
    let entry = manifest
        .fixtures
        .iter()
        .find(|entry| entry.path == entry_name)
        .ok_or_else(|| format!("fixture entry not found: {entry_name}"))?;
    let source = fixture_dir().join(&entry.path);
    if sha256_file(&source)? != entry.sha256 {
        return Err(format!("fixture checksum mismatch: {entry_name}"));
    }
    let mut source_file = File::open(&source).map_err(|error| error.to_string())?;
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| error.to_string())?;
    if io::copy(&mut source_file, &mut destination_file).is_err() {
        cleanup_failed_destination(destination, &fixture_root);
        return Err("fixture copy failed".into());
    }
    drop(destination_file);
    let source_checksum = sha256_file(&source);
    let destination_checksum = sha256_file(destination);
    if !matches!(&source_checksum, Ok(checksum) if checksum == &entry.sha256)
        || !matches!(&destination_checksum, Ok(checksum) if checksum == &entry.sha256)
    {
        cleanup_failed_destination(destination, &fixture_root);
        return Err(format!(
            "fixture checksum mismatch after copy: {entry_name}"
        ));
    }
    Ok(entry.clone())
}

pub(crate) fn load_manifest() -> Result<RecoveryFixtureManifest, String> {
    let contents = fs::read_to_string(fixture_dir().join("manifest.json"))
        .map_err(|error| error.to_string())?;
    let manifest = serde_json::from_str(&contents).map_err(|error| error.to_string())?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    Ok(hex(&Sha256::digest(bytes)))
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recovery")
}

fn validate_destination(destination: &Path) -> Result<PathBuf, String> {
    if !destination.is_absolute() {
        return Err("fixture destination must be absolute".into());
    }
    let fixture_root = fixture_dir()
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if destination.starts_with(&fixture_root) {
        return Err("fixture destination must be outside the repository fixture directory".into());
    }
    let parent = canonical_existing_parent(destination)?;
    if parent.starts_with(&fixture_root) {
        return Err(
            "fixture destination parent must be outside the repository fixture directory".into(),
        );
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => Err("fixture destination already exists".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(fixture_root),
        Err(error) => Err(error.to_string()),
    }
}

fn canonical_existing_parent(destination: &Path) -> Result<PathBuf, String> {
    let mut parent = destination
        .parent()
        .ok_or_else(|| "fixture destination must have a parent".to_owned())?;
    loop {
        match parent.canonicalize() {
            Ok(canonical) => return Ok(canonical),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                parent = parent
                    .parent()
                    .ok_or_else(|| "fixture destination parent does not exist".to_owned())?;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn cleanup_failed_destination(destination: &Path, fixture_root: &Path) {
    let safe_parent = destination
        .parent()
        .and_then(|parent| parent.canonicalize().ok())
        .is_some_and(|parent| !parent.starts_with(fixture_root));
    if safe_parent
        && fs::symlink_metadata(destination).is_ok_and(|metadata| metadata.file_type().is_file())
    {
        let _ = fs::remove_file(destination);
    }
}

fn validate_manifest(manifest: &RecoveryFixtureManifest) -> Result<(), String> {
    if manifest.manifest_version != 1 || manifest.fixtures.is_empty() {
        return Err("unsupported or empty recovery fixture manifest".into());
    }
    let mut paths = std::collections::BTreeSet::new();
    for entry in &manifest.fixtures {
        validate_entry(entry)?;
        if !paths.insert(&entry.path) {
            return Err(format!("duplicate fixture path: {}", entry.path));
        }
    }
    Ok(())
}

fn validate_entry(entry: &RecoveryFixtureEntry) -> Result<(), String> {
    let path = Path::new(&entry.path);
    if !matches!(path.components().next(), Some(Component::Normal(_)))
        || path.components().count() != 1
        || path.file_name().is_none()
    {
        return Err("fixture path must be filename-only".into());
    }
    if !lower_hex(&entry.source_commit, 40)
        || !lower_hex(&entry.sha256, 64)
        || entry.source_ref.is_empty()
        || entry.writer_file.is_empty()
        || entry.writer_snapshot.is_empty()
        || entry.writer_snapshot.starts_with('/')
        || entry.writer_snapshot.contains("..")
        || !lower_hex(&entry.writer_snapshot_sha256, 64)
        || entry.writer_symbol.is_empty()
        || entry.writer_test.is_empty()
        || entry.schema_version <= 0
        || entry.expected_rows.is_empty()
        || !known_profile_domain(entry.integrity_profile, &entry.digest_domain)
    {
        return Err(format!("invalid fixture entry: {}", entry.path));
    }
    for row in &entry.expected_rows {
        let primary_key_column = primary_key_column(&row.table);
        if row.table != expected_table(&entry.digest_domain)
            || row.columns.is_empty()
            || !lower_hex(&row.primary_key_hex, 32)
            || primary_key_column.and_then(|column| row.columns.get(column))
                != Some(&row.primary_key_hex)
            || row
                .columns
                .iter()
                .any(|(name, value)| name.is_empty() || value.is_empty())
        {
            return Err(format!("invalid expected row: {}", entry.path));
        }
    }
    Ok(())
}

fn expected_table(domain: &str) -> &str {
    match domain {
        "TaskRun" | "Conversation" => "events",
        "ProviderPreparedV1" => "provider_prepared_requests",
        _ => "",
    }
}

fn primary_key_column(table: &str) -> Option<&str> {
    match table {
        "events" => Some("event_id"),
        "provider_prepared_requests" => Some("call_id"),
        _ => None,
    }
}

fn known_profile_domain(profile: u16, domain: &str) -> bool {
    matches!(
        (profile, domain),
        (1, "TaskRun") | (2, "Conversation") | (1, "ProviderPreparedV1")
    )
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_rejects_empty_expected_row_primary_key() {
        let mut manifest = load_manifest().unwrap();
        manifest.fixtures[0].expected_rows[0]
            .primary_key_hex
            .clear();

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn manifest_rejects_short_expected_row_primary_key() {
        let mut manifest = load_manifest().unwrap();
        manifest.fixtures[0].expected_rows[0].primary_key_hex = "00".into();

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn manifest_rejects_mismatched_expected_row_primary_key() {
        let mut manifest = load_manifest().unwrap();
        manifest.fixtures[0].expected_rows[0].primary_key_hex =
            "00000000000000000000000000000000".into();

        assert!(validate_manifest(&manifest).is_err());
    }
}
