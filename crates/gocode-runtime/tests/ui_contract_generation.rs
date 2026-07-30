use std::fs;
use std::path::{Path, PathBuf};

use gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH;
use gocode_runtime::contract_generation::{
    GENERATED_ARTIFACT_PATHS, check_ui_contract, generate_ui_contract,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn generated_files(root: &Path) -> Vec<PathBuf> {
    fn visit(root: &Path, current: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(current).expect("read generated contract directory") {
            let path = entry.expect("read generated contract entry").path();
            if path.is_dir() {
                visit(root, &path, files);
            } else {
                files.push(path.strip_prefix(root).unwrap().to_owned());
            }
        }
    }

    let mut files = Vec::new();
    visit(root, root, &mut files);
    files.sort();
    files
}

fn assert_sorted_json(value: &Value) {
    match value {
        Value::Object(object) => {
            let keys = object.keys().collect::<Vec<_>>();
            assert!(
                keys.windows(2).all(|pair| pair[0] < pair[1]),
                "JSON object keys are not strictly sorted: {keys:?}"
            );
            for value in object.values() {
                assert_sorted_json(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_sorted_json(value);
            }
        }
        _ => {}
    }
}

fn resolve_json_pointer(document: &Value, fragment: &str) -> bool {
    fragment.is_empty()
        || fragment == "#"
        || fragment
            .strip_prefix("#/")
            .and_then(|pointer| document.pointer(&format!("/{pointer}")))
            .is_some()
}

fn assert_local_refs_resolve(document_path: &Path, value: &Value) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                let (relative_path, fragment) = reference
                    .split_once('#')
                    .map_or((reference, ""), |(path, fragment)| {
                        (path, if fragment.is_empty() { "#" } else { fragment })
                    });
                if relative_path.is_empty() {
                    assert!(
                        resolve_json_pointer(value, fragment),
                        "unresolved local fragment {reference}"
                    );
                } else {
                    let target = document_path.parent().unwrap().join(relative_path);
                    let target_value: Value =
                        serde_json::from_slice(&fs::read(&target).expect("read referenced schema"))
                            .expect("parse referenced schema");
                    let fragment = reference
                        .split_once('#')
                        .map_or("", |(_, fragment)| fragment);
                    assert!(
                        fragment.is_empty()
                            || target_value
                                .pointer(&format!("/{}", fragment.trim_start_matches('/')))
                                .is_some(),
                        "unresolved reference {reference} from {}",
                        document_path.display()
                    );
                }
            }
            for nested in object.values() {
                assert_local_refs_resolve(document_path, nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                assert_local_refs_resolve(document_path, nested);
            }
        }
        _ => {}
    }
}

#[test]
fn generation_is_deterministic_and_every_json_artifact_is_canonical() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    generate_ui_contract(first.path()).unwrap();
    generate_ui_contract(second.path()).unwrap();

    let expected = GENERATED_ARTIFACT_PATHS
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let first_files = generated_files(first.path());
    assert_eq!(first_files, expected);
    assert_eq!(generated_files(second.path()), expected);

    for relative_path in first_files {
        let first_bytes = fs::read(first.path().join(&relative_path)).unwrap();
        let second_bytes = fs::read(second.path().join(&relative_path)).unwrap();
        assert_eq!(first_bytes, second_bytes, "{}", relative_path.display());
        assert_eq!(
            first_bytes.last(),
            Some(&b'\n'),
            "{}",
            relative_path.display()
        );
        assert!(
            !first_bytes.ends_with(b"\n\n"),
            "{} has more than one trailing newline",
            relative_path.display()
        );
        if relative_path
            .extension()
            .is_some_and(|value| value == "json")
        {
            let value: Value = serde_json::from_slice(&first_bytes).unwrap();
            assert_sorted_json(&value);
        }
    }
}

#[test]
fn schemas_compile_goldens_validate_and_openapi_refs_resolve_locally() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();

    for path in [
        "schemas/local-runtime-profile-v2.schema.json",
        "schemas/local-session-v1.schema.json",
        "schemas/replay-v1.schema.json",
        "schemas/sse-v1.schema.json",
    ] {
        let schema: Value =
            serde_json::from_slice(&fs::read(output.path().join(path)).unwrap()).unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{path} did not compile: {error}"));
    }

    for (schema_path, golden_path) in [
        (
            "schemas/local-session-v1.schema.json",
            "golden/local-session.json",
        ),
        (
            "schemas/replay-v1.schema.json",
            "golden/replay-conversation.json",
        ),
        (
            "schemas/replay-v1.schema.json",
            "golden/replay-taskrun.json",
        ),
        ("schemas/sse-v1.schema.json", "golden/sse-delivery.json"),
    ] {
        let schema: Value =
            serde_json::from_slice(&fs::read(output.path().join(schema_path)).unwrap()).unwrap();
        let validator = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let golden: Value =
            serde_json::from_slice(&fs::read(output.path().join(golden_path)).unwrap()).unwrap();
        assert!(
            validator.is_valid(&golden),
            "{golden_path} does not validate against {schema_path}"
        );
    }

    let openapi_path = output.path().join("openapi.json");
    let openapi: Value = serde_json::from_slice(&fs::read(&openapi_path).unwrap()).unwrap();
    assert_eq!(openapi["openapi"], "3.1.0");
    assert_local_refs_resolve(&openapi_path, &openapi);
}

#[test]
fn bundle_digest_is_content_only_and_check_never_rewrites() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();

    let bundle_bytes = fs::read(output.path().join("bundle.json")).unwrap();
    let digest = fs::read_to_string(output.path().join("bundle.sha256")).unwrap();
    assert_eq!(
        digest.trim_end(),
        hex::encode(Sha256::digest(&bundle_bytes))
    );
    assert_eq!(digest.trim_end(), PUBLISHED_BUNDLE_HASH);
    let bundle: Value = serde_json::from_slice(&bundle_bytes).unwrap();
    assert_eq!(bundle["apiProfileId"], "gocode-ui-client/1");
    assert_eq!(bundle["transportProfileId"], "gocode-local-runtime/2");
    assert_eq!(
        bundle["publishedCapabilities"],
        serde_json::json!([
            "conversation.create.v1",
            "conversation.generate_text.v1",
            "conversation.list_messages.v1"
        ])
    );
    assert_eq!(bundle["capabilityCatalog"].as_array().unwrap().len(), 9);
    assert!(
        !bundle
            .as_object()
            .unwrap()
            .keys()
            .any(|key| key.to_ascii_lowercase().contains("commit"))
    );

    check_ui_contract(output.path()).unwrap();
    let openapi_path = output.path().join("openapi.json");
    let replacement = b"{\"changed\":true}\n";
    fs::write(&openapi_path, replacement).unwrap();
    assert!(check_ui_contract(output.path()).is_err());
    assert_eq!(fs::read(openapi_path).unwrap(), replacement);

    generate_ui_contract(output.path()).unwrap();
    let stale_path = output.path().join("golden/stale.json");
    fs::write(&stale_path, b"{}\n").unwrap();
    assert!(check_ui_contract(output.path()).is_err());
    assert_eq!(fs::read(stale_path).unwrap(), b"{}\n");
}
