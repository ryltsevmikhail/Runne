//! Builder determinism (Plan Task 17 Step 1 / MANIFEST_TOOLING
//! §Детерминизм): identical inputs → byte-identical canonical bytes;
//! output validates through the immutable identity path.

mod builder_common;

use builder_common::{full_user, gguf_with_metadata};
use runne_local_model::{BUILDER_CONTRACT_VERSION, build_candidate_manifest};
use std::io::Cursor;

fn input(bytes: &[u8]) -> (Cursor<Vec<u8>>, runne_local_model::UserSupplied) {
    (Cursor::new(bytes.to_vec()), full_user())
}

#[test]
fn same_inputs_yield_byte_identical_manifest() {
    let bytes = gguf_with_metadata();
    let (mut r1, u1) = input(&bytes);
    let (mut r2, u2) = input(&bytes);
    let a = build_candidate_manifest(&mut r1, &u1, BUILDER_CONTRACT_VERSION).expect("build 1");
    let b = build_candidate_manifest(&mut r2, &u2, BUILDER_CONTRACT_VERSION).expect("build 2");
    assert_eq!(a.canonical_bytes, b.canonical_bytes);
    assert_eq!(a.manifest_digest, b.manifest_digest);
}

#[test]
fn output_validates_through_identity_path() {
    let bytes = gguf_with_metadata();
    let (mut r, u) = input(&bytes);
    let built = runne_local_model::build_candidate_manifest(&mut r, &u, BUILDER_CONTRACT_VERSION)
        .expect("build");
    let verified = runne_local_model::ModelManifestV1::parse_and_verify(&built.canonical_bytes)
        .expect("built manifest must satisfy the immutable identity path");
    assert_eq!(
        verified.manifest_id(),
        format!("local:test-model:r1:{}", built.manifest_digest)
    );
}

#[test]
fn changed_builder_revision_changes_candidate_not_identity() {
    let bytes = gguf_with_metadata();
    let (mut r1, u1) = input(&bytes);
    let (mut r2, u2) = input(&bytes);
    let v1 = build_candidate_manifest(&mut r1, &u1, "0.1.0").expect("v1");
    let v2 = build_candidate_manifest(&mut r2, &u2, "0.2.0").expect("v2");
    assert_ne!(v1.canonical_bytes, v2.canonical_bytes);
    // The difference is exactly the recorded runtime floor; model id
    // and revision stay user-owned (identity fields unchanged).
    let text1 = String::from_utf8(v1.canonical_bytes.clone()).expect("utf8");
    let text2 = String::from_utf8(v2.canonical_bytes.clone()).expect("utf8");
    assert!(text1.contains("\"minCompatibleRuntime\":\"0.1.0\""));
    assert!(text2.contains("\"minCompatibleRuntime\":\"0.2.0\""));
}
