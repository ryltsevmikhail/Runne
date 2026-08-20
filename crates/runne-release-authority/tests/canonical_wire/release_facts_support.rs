use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn manifest(digest: &str) -> Value {
    map(vec![
        ("app_version", json!("1.0.0")),
        (
            "artifacts",
            json!([
                artifact(
                    "linux-appimage",
                    "linux-ubuntu-24_04-x86_64-production",
                    "linux",
                    "x86_64",
                    digest,
                    1
                ),
                artifact(
                    "linux-deb",
                    "linux-ubuntu-24_04-x86_64-production",
                    "linux",
                    "x86_64",
                    digest,
                    2
                ),
                artifact(
                    "macos-app-development-adhoc",
                    "macos-14-arm64-development-preview",
                    "macos",
                    "arm64",
                    digest,
                    3
                ),
                artifact(
                    "macos-dmg-development-adhoc",
                    "macos-14-arm64-development-preview",
                    "macos",
                    "arm64",
                    digest,
                    4
                ),
                artifact(
                    "windows-installer-unsigned",
                    "windows-11-24h2-x86_64-production",
                    "windows",
                    "x86_64",
                    digest,
                    5
                ),
            ]),
        ),
        ("bootstrap_sha256", json!(digest)),
        ("bundle_identity", json!("gocode-desktop")),
        (
            "bundled_runtime",
            json!({"sha256":digest,"version":"1.0.0"}),
        ),
        ("candidate_sha256", json!(digest)),
        (
            "macos_preview",
            json!({"artifact_slot_ids":["macos-app-development-adhoc","macos-dmg-development-adhoc"],"disposition":"development_preview","platform_scope_id":"macos-14-arm64-development-preview","publication_allowed":false}),
        ),
        ("matrix_sha256", json!(digest)),
        ("policy_sha256", json!(digest)),
        ("release_sequence", json!(1)),
        (
            "schema_version",
            json!("gocode.release.unsigned-candidate-manifest/1"),
        ),
        ("subject_sha256", json!(digest)),
    ])
}

fn artifact(
    slot: &str,
    scope: &str,
    platform: &str,
    architecture: &str,
    digest: &str,
    length: u64,
) -> Value {
    json!({"architecture":architecture,"artifact_sha256":digest,"artifact_slot_id":slot,"byte_length":length,"minimum_os_policy":{"policy_id":"v1-minimum-os","policy_sha256":digest},"platform":platform,"platform_scope_id":scope,"profile_bindings":[{"bundle_sha256":digest,"profile_id":"gocode-bundled-runtime"}]})
}

fn map(values: Vec<(&str, Value)>) -> Value {
    json!(values.into_iter().collect::<BTreeMap<_, _>>())
}
