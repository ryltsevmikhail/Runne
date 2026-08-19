use std::fs;
use std::path::{Path, PathBuf};

use runne_api::CanonicalReplayPayloadV1;
use runne_domain::command::TerminalResult;
use runne_domain::task_run::TaskRunEvent;
use runne_runtime::bundle::{
    BASE_RUNTIME_CAPABILITIES, PUBLISHED_BUNDLE_HASH, PUBLISHED_RUNTIME_CAPABILITIES,
    RUNTIME_CAPABILITY_CATALOG,
};
use runne_runtime::contract_generation::{
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
