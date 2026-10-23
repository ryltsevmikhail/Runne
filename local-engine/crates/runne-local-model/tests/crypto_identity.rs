//! SHA256 public manifest identity known answer; no model or platform activation.
use runne_local_model::{ModelManifestV1, compute_digest};
use sha2::{Digest, Sha256};

#[test]
fn sha256_public_manifest_preimage_digest_and_model_id() {
    let golden = include_str!("../../../docs/golden/local-engine/model-manifest-v1.json");
    let expected = "sha256:365ffe5abeedf5ee722b26792aa4962d47c83f58e87b093f0cad2a8dea64140d";
    let mut value: serde_json::Value = serde_json::from_str(golden).unwrap();
    assert_eq!(compute_digest(&value).unwrap().as_str(), expected);
    assert!(
        value
            .as_object_mut()
            .unwrap()
            .remove("manifestDigest")
            .is_some()
    );
    let preimage = serde_json_canonicalizer::to_vec(&value).unwrap();
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&preimage)));
    assert_eq!(digest, expected);
    let verified = ModelManifestV1::parse_and_verify(golden.as_bytes()).unwrap();
    assert_eq!(verified.canonical(), golden.trim_end());
    assert_eq!(verified.digest().as_str(), expected);
    assert_eq!(
        verified.manifest_id(),
        format!("local:qwen3-4b-instruct:r2026-08-01:{expected}")
    );
    println!(
        "CRYPTO public-model-preimage={} digest={} id={}",
        hex::encode(preimage),
        digest,
        verified.manifest_id()
    );
}
