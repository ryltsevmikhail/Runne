//! RC1 immutable release-facts contract vectors.

use runne_release_authority::{AuthorityError, CanonicalPayloadKind, InspectedCanonicalPayload};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn accepts_the_closed_v1_release_facts_manifest() {
    assert!(
        InspectedCanonicalPayload::parse(CanonicalPayloadKind::UnsignedManifest, &manifest())
            .is_ok()
    );
}

#[test]
fn rejects_release_fact_omission_reorder_duplicates_and_public_macos_preview() {
    let cases = [
        remove("app_version"),
        replace_path("artifacts.1.artifact_slot_id", json!("linux-appimage")),
        replace_path("bundle_identity", json!("BadIdentity")),
        replace_path(
            "artifacts.0.profile_bindings",
            json!([profile("z", B), profile("a", A)]),
        ),
        replace_path("macos_preview.publication_allowed", json!(true)),
        replace_path("artifacts", json!([])),
    ];
    for raw in cases {
        assert_eq!(
            InspectedCanonicalPayload::parse(CanonicalPayloadKind::UnsignedManifest, &raw),
            Err(AuthorityError::NonCanonicalPayload)
        );
    }
}

#[test]
fn binds_rc1_decision_to_the_exact_manifest_release_facts() {
    let manifest = manifest();
    let manifest_digest = hex(Sha256::digest(&manifest[..manifest.len() - 1]));
    let raw_decision = decision(&manifest_digest);
    assert!(
        InspectedCanonicalPayload::parse(CanonicalPayloadKind::Rc1Decision, &raw_decision).is_ok()
    );
    let replaced = decision(&hex(Sha256::digest(b"other release facts")));
    assert!(InspectedCanonicalPayload::parse(CanonicalPayloadKind::Rc1Decision, &replaced).is_ok());
    assert_ne!(raw_decision, replaced);
}

fn manifest() -> Vec<u8> {
    canonical(&map(vec![
        ("app_version", json!("1.0.0")),
        (
            "artifacts",
            json!([
                artifact(
                    "linux-appimage",
                    "linux-ubuntu-24_04-x86_64-production",
                    "linux",
                    "x86_64",
                    A,
                    1
                ),
                artifact(
                    "linux-deb",
                    "linux-ubuntu-24_04-x86_64-production",
                    "linux",
                    "x86_64",
                    B,
                    2
                ),
                artifact(
                    "macos-app-development-adhoc",
                    "macos-14-arm64-development-preview",
                    "macos",
                    "arm64",
                    A,
                    3
                ),
                artifact(
                    "macos-dmg-development-adhoc",
                    "macos-14-arm64-development-preview",
                    "macos",
                    "arm64",
                    B,
                    4
                ),
                artifact(
                    "windows-installer-unsigned",
                    "windows-11-24h2-x86_64-production",
                    "windows",
                    "x86_64",
                    A,
                    5
                ),
            ]),
        ),
        ("bootstrap_sha256", json!(A)),
        ("bundle_identity", json!("gocode-desktop")),
        ("bundled_runtime", json!({"sha256":A,"version":"1.0.0"})),
        ("candidate_sha256", json!(A)),
        (
            "macos_preview",
            json!({"artifact_slot_ids":["macos-app-development-adhoc","macos-dmg-development-adhoc"],"disposition":"development_preview","platform_scope_id":"macos-14-arm64-development-preview","publication_allowed":false}),
        ),
        ("matrix_sha256", json!(A)),
        ("policy_sha256", json!(A)),
        ("release_sequence", json!(1)),
        (
            "schema_version",
            json!("gocode.release.unsigned-candidate-manifest/1"),
        ),
        ("subject_sha256", json!(A)),
    ]))
}

fn artifact(
    slot: &str,
    scope: &str,
    platform: &str,
    architecture: &str,
    digest: &str,
    length: u64,
) -> Value {
    json!({"architecture":architecture,"artifact_sha256":digest,"artifact_slot_id":slot,"byte_length":length,"minimum_os_policy":{"policy_id":"v1-minimum-os","policy_sha256":A},"platform":platform,"platform_scope_id":scope,"profile_bindings":[profile("gocode-bundled-runtime", A)]})
}

fn decision(release_facts_sha256: &str) -> Vec<u8> {
    canonical(&map(vec![
        (
            "approver",
            json!({"account_id":"account","key_id":"key","lane_id":"lane","principal_id":"principal","signature_profile_id":"profile"}),
        ),
        ("bootstrap_sha256", json!(A)),
        ("candidate_binding_sha256", json!(A)),
        ("candidate_sha256", json!(A)),
        ("disposition", json!("qualified_unsigned")),
        ("expires_at", json!(2)),
        ("external_effects", json!([])),
        ("matrix_sha256", json!(A)),
        ("policy_sha256", json!(A)),
        ("publication_allowed", json!(false)),
        ("release_facts_sha256", json!(release_facts_sha256)),
        ("revocation_epoch", json!(1)),
        (
            "schema_version",
            json!("gocode.release.rc1-qualification-decision/1"),
        ),
        ("signing_allowed", json!(false)),
        ("subject_sha256", json!(A)),
        ("valid_from", json!(1)),
    ]))
}

fn profile(id: &str, digest: &str) -> Value {
    json!({"bundle_sha256":digest,"profile_id":id})
}

fn remove(field: &str) -> Vec<u8> {
    let mut value = value();
    value.as_object_mut().unwrap().remove(field);
    canonical(&value)
}

fn replace_path(path: &str, replacement: Value) -> Vec<u8> {
    let mut value = value();
    let mut fields = path.split('.').peekable();
    let mut current = &mut value;
    while let Some(field) = fields.next() {
        if fields.peek().is_none() {
            current
                .as_object_mut()
                .unwrap()
                .insert(field.into(), replacement);
            break;
        }
        current = match field.parse::<usize>() {
            Ok(index) => &mut current.as_array_mut().unwrap()[index],
            Err(_) => current.as_object_mut().unwrap().get_mut(field).unwrap(),
        };
    }
    canonical(&value)
}

fn value() -> Value {
    serde_json::from_slice(&manifest()).unwrap()
}

fn map(values: Vec<(&str, Value)>) -> Value {
    json!(values.into_iter().collect::<BTreeMap<_, _>>())
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut raw = serde_json::to_vec(&value).unwrap();
    raw.push(b'\n');
    raw
}

fn hex(digest: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;

    digest
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut value, byte| {
            write!(value, "{byte:02x}").expect("writing to String cannot fail");
            value
        })
}
