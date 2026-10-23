//! Pure root-resolved path-consumer contract; never starts platform services.
#[path = "../../../local-engine/crates/runne-local-model/tests/builder_common/mod.rs"]
mod builder_fixture;

use runne_local_model::{ModelManifestV1, build_candidate_manifest, compute_digest};
use sha2::{Digest, Sha256};

#[test]
fn root_manifest_public_identity_and_bytes() {
    let golden =
        include_str!("../../../local-engine/docs/golden/local-engine/model-manifest-v1.json");
    let expected =
        include_str!("../../../local-engine/docs/golden/local-engine/model-manifest-v1.sha256")
            .trim();
    let verified = ModelManifestV1::parse_and_verify(golden.as_bytes()).expect("frozen fixture");
    assert_eq!(
        verified.canonical().as_bytes(),
        golden.trim_end().as_bytes()
    );
    assert_eq!(verified.digest().as_str(), expected);
    assert_eq!(
        verified.manifest_id(),
        format!("local:qwen3-4b-instruct:r2026-08-01:{expected}")
    );
    let value = serde_json::from_str(golden).unwrap();
    assert_eq!(compute_digest(&value).unwrap().as_str(), expected);
    println!(
        "ROOT manifest bytes={} sha256={:x} id={}",
        hex::encode(verified.canonical()),
        Sha256::digest(verified.canonical()),
        verified.manifest_id()
    );
}

#[test]
fn root_builder_frozen_bytes_and_digest() {
    let built = build_candidate_manifest(
        &mut std::io::Cursor::new(builder_fixture::gguf_with_metadata()),
        &builder_fixture::full_user(),
        runne_local_model::BUILDER_CONTRACT_VERSION,
    )
    .expect("synthetic zero-tensor fixture");
    let frozen =
        include_str!("../../../local-engine/docs/golden/local-engine/builder/golden-manifest.json")
            .trim_end();
    assert_eq!(built.canonical_bytes, frozen.as_bytes());
    let value = serde_json::from_str(frozen).unwrap();
    assert_eq!(
        built.manifest_digest,
        compute_digest(&value).unwrap().as_str()
    );
    println!(
        "ROOT builder bytes={} sha256={:x} digest={}",
        hex::encode(&built.canonical_bytes),
        Sha256::digest(&built.canonical_bytes),
        built.manifest_digest
    );
}
