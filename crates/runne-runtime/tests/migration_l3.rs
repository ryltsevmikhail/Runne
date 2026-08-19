//! L3 golden-fixture migration tests.
//!
//! Эти тесты проверяют целостность golden fixtures в `docs/golden/migration/`:
//! - парсинг JSON без мутации
//! - совпадение `source_sha` с pinned baseline
//! - отсутствие blacklisted keys
//! - валидность digest sidecar

use runne_runtime::migration_shadow::PureShadowExecutor;
use sha2::{Digest, Sha256};

#[test]
fn import_dry_run_reads_golden_fixture_without_mutation() {
    let fixture = include_bytes!("../../../docs/golden/migration/baseline-v1.json");
    // Парсим fixture, проверяем что source_sha совпадает
    let parsed: serde_json::Value = serde_json::from_slice(fixture).unwrap();
    assert_eq!(
        parsed["source_sha"].as_str().unwrap(),
        "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
    );
}

#[test]
fn unsanitized_fixture_rejected_before_evaluation() {
    let fixture_root = format!("{}/../../docs/golden/migration", env!("CARGO_MANIFEST_DIR"));
    let schema_path = format!(
        "{}/../../docs/schemas/migration-evidence-v1.schema.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let temp = std::env::temp_dir().join(format!(
        "runne-migration-l3-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let temp_golden = temp.join("docs/golden/migration");
    let temp_schema = temp.join("docs/schemas/migration-evidence-v1.schema.json");
    std::fs::create_dir_all(&temp_golden).unwrap();
    std::fs::create_dir_all(temp_schema.parent().unwrap()).unwrap();
    std::fs::copy(&schema_path, &temp_schema).unwrap();
    for entry in std::fs::read_dir(fixture_root).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), temp_golden.join(entry.file_name())).unwrap();
    }

    let fixture = temp_golden.join("baseline-v1.json");
    let mut parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture).unwrap()).unwrap();
    parsed["prompt"] = serde_json::Value::String("private".to_owned());
    let canonical = jcs_canonicalize(&mut parsed);
    let digest = format!("sha256:{:x}", Sha256::digest(&canonical));
    std::fs::write(&fixture, canonical).unwrap();
    std::fs::write(fixture.with_extension("json.digest"), digest).unwrap();

    let output = std::process::Command::new("python3")
        .arg(format!(
            "{}/../../scripts/verify-migration-artifacts.py",
            env!("CARGO_MANIFEST_DIR")
        ))
        .arg("--golden-dir")
        .arg(&temp_golden)
        .arg("--schema")
        .arg(&temp_schema)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&temp).unwrap();
    let status = output.status;
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(
        !status.success(),
        "verifier accepted forbidden prompt: {}",
        output
    );
    assert!(
        output.contains("blacklisted key 'prompt' found"),
        "verifier did not report the blacklisted prompt key: {output}"
    );
}

#[test]
fn all_golden_fixtures_parse_as_valid_json() {
    for path in &[
        "baseline-v1.json",
        "import-report-v1.json",
        "shadow-diff-v1.json",
        "cutover-manifest-v1.json",
        "rollback-manifest-v1.json",
    ] {
        let full = format!("../../docs/golden/migration/{path}");
        let data = std::fs::read(&full).unwrap_or_else(|_| panic!("missing: {full}"));
        let _: serde_json::Value =
            serde_json::from_slice(&data).unwrap_or_else(|e| panic!("invalid JSON in {path}: {e}"));
    }
}

/// JCS-like canonicalization: recursively sort object keys and serialize
/// without whitespace (matches `scripts/verify-migration-artifacts.py`).
fn jcs_canonicalize(value: &mut serde_json::Value) -> Vec<u8> {
    sort_keys_recursive(value);
    serde_json::to_vec(value).expect("JCS canonicalization failed")
}

fn sort_keys_recursive(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Sort entries by key and rebuild in sorted order.
            let mut entries: Vec<_> = std::mem::take(map).into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            *map = entries.into_iter().collect();
            for (_, v) in map.iter_mut() {
                sort_keys_recursive(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                sort_keys_recursive(v);
            }
        }
        _ => {}
    }
}

#[test]
fn golden_fixture_digests_match_sidecars() {
    for path in &[
        "baseline-v1.json",
        "import-report-v1.json",
        "shadow-diff-v1.json",
        "cutover-manifest-v1.json",
        "rollback-manifest-v1.json",
    ] {
        let full = format!("../../docs/golden/migration/{path}");
        let data = std::fs::read(&full).unwrap_or_else(|_| panic!("missing: {full}"));
        let mut parsed: serde_json::Value =
            serde_json::from_slice(&data).unwrap_or_else(|e| panic!("invalid JSON in {path}: {e}"));
        let canonical = jcs_canonicalize(&mut parsed);
        let hash = format!("sha256:{:x}", Sha256::digest(&canonical));

        let digest_path = format!("{full}.digest");
        let expected = std::fs::read_to_string(&digest_path)
            .unwrap_or_else(|_| panic!("missing: {digest_path}"))
            .trim()
            .to_string();

        assert_eq!(hash, expected, "digest mismatch for {path}");
    }
}

#[test]
fn pure_shadow_executor_has_zero_canonical_writes() {
    use runne_runtime::migration_shadow::RecordedFixtureCatalog;
    let catalog = RecordedFixtureCatalog::new([]).unwrap();
    let executor = PureShadowExecutor::new(catalog);
    assert_eq!(executor.canonical_write_count(), 0);
}
