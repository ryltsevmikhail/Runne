//! Catalog tests: deterministic list order, exact identity lookup,
//! admission exactly-once.

use runne_local_model::gguf_limits::GGUF_MAGIC;
use runne_model_store::{LicenseAcceptance, ModelArtifactStore};
use std::io::Cursor;

fn manifest_for(model_id: &str, revision: &str, payload: &[u8]) -> String {
    let _ = payload;
    let artifact_digest = format!("sha256:{}", {
        use sha2::{Digest, Sha256};
        let mut image = Vec::new();
        image.extend_from_slice(&GGUF_MAGIC);
        image.extend_from_slice(&3u32.to_le_bytes());
        image.extend_from_slice(&0u64.to_le_bytes());
        image.extend_from_slice(&0u64.to_le_bytes());
        hex::encode(Sha256::digest(&image))
    });
    format!(
        "{{\"artifacts\":[{{\"byteLength\":24,\"contentType\":\"application/gguf\",\"digest\":\"{artifact_digest}\",\"role\":\"model\"}}],\"capabilities\":{{\"contextMaxTokens\":4096,\"modalities\":[\"text\"],\"outputMaxTokens\":1024,\"reasoning\":false,\"streaming\":true,\"structuredOutput\":false,\"tools\":false}},\"chatTemplate\":{{\"id\":\"chat\",\"revision\":\"1\",\"sourceDigest\":\"sha256:63bce8d4edf0cd46fffe9c93a06ed34806202956d17a36a94df37388d9149b51\"}},\"compatibility\":{{\"backendProfiles\":[{{\"id\":\"llama-cpp-cpu-macos-arm64-v1\",\"revision\":\"v1\"}}]}},\"format\":\"GGUF\",\"hardwareRequirements\":{{\"arch\":\"arm64\",\"minRamBytes\":1,\"os\":\"macos\"}},\"license\":\"Apache-2.0\",\"manifestDigest\":\"__MDG__\",\"minCompatibleRuntime\":\"0.1.0\",\"modelID\":\"{model_id}\",\"modelRevision\":\"{revision}\",\"provenance\":{{\"acquiredAt\":\"2026-09-04T00:00:00Z\",\"publisher\":\"p\",\"sourceDigest\":\"sha256:25a6634263c1b1f6fc4697a04e2b9904ea4b042a89af59dc93ec1f5d44848a26\",\"sourceUri\":\"https://x.gguf\"}},\"schemaVersion\":\"ModelManifestV1\",\"tokenizer\":{{\"configDigest\":\"sha256:1a7674eb4ee78df7e1ac439a93c3fa8e3c945784d4dec9fd8e3011738b2f1d62\",\"family\":\"bpe\",\"revision\":\"1\"}},\"toolProtocol\":{{\"id\":\"tp\",\"revision\":\"1\",\"schemaDigest\":\"sha256:7c9bbe5ec9b3fb774e8fa0f54247e93c34ddf8e5d16fe3073420de0ae81a262d\",\"semantics\":\"s\"}}}}"
    )
}

fn gguf(_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GGUF_MAGIC);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

/// Computes manifestDigest over the sorted-key preimage (test manifests
/// are ASCII-sorted with no spaces, so JCS == literal bytes) and splices
/// the digest member in at its sorted position.
fn with_manifest_digest(m: String) -> String {
    use sha2::{Digest, Sha256};
    let member = "\"manifestDigest\":\"__MDG__\",";
    let preimage = m.replace(member, "");
    let digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(preimage.as_bytes()))
    );
    m.replace("__MDG__", &digest)
}

#[test]
fn admission_is_exactly_once() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    let artifact = gguf(b"payload-1");
    let candidate = store
        .stage_import(
            with_manifest_digest(manifest_for("m1", "r1", &artifact)).as_bytes(),
            &mut Cursor::new(artifact),
        )
        .expect("stage");
    let accepted = LicenseAcceptance {
        license_digest: {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(candidate.license.as_bytes()))
        },
    };
    store
        .admit(&candidate.candidate_id, &accepted)
        .expect("admit");
    let err = store
        .admit(&candidate.candidate_id, &accepted)
        .expect_err("second admit");
    assert!(matches!(
        err,
        runne_model_store::StoreError::AdmissionConflict
    ));
}

#[test]
fn list_order_deterministic() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    for (id, rev) in [("b", "2"), ("a", "1"), ("a", "0")] {
        let artifact = gguf(format!("{id}{rev}").as_bytes());
        let candidate = store
            .stage_import(
                with_manifest_digest(manifest_for(id, rev, &artifact)).as_bytes(),
                &mut Cursor::new(artifact),
            )
            .expect("stage");
        let accepted = LicenseAcceptance {
            license_digest: {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(candidate.license.as_bytes()))
            },
        };
        store
            .admit(&candidate.candidate_id, &accepted)
            .expect("admit");
    }
    let list = store.list().expect("list");
    let ids: Vec<String> = list
        .iter()
        .map(|i| format!("{}:{}", i.model_id, i.model_revision))
        .collect();
    assert_eq!(ids, vec!["a:0", "a:1", "b:2"]);
}

#[test]
fn get_exact_requires_full_identity() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    let artifact = gguf(b"payload-x");
    let candidate = store
        .stage_import(
            with_manifest_digest(manifest_for("m1", "r1", &artifact)).as_bytes(),
            &mut Cursor::new(artifact),
        )
        .expect("stage");
    let accepted = LicenseAcceptance {
        license_digest: {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(candidate.license.as_bytes()))
        },
    };
    store
        .admit(&candidate.candidate_id, &accepted)
        .expect("admit");
    assert!(
        store
            .get_exact("m1", &candidate.manifest_digest)
            .expect("get")
            .is_some()
    );
    assert!(
        store
            .get_exact("other", &candidate.manifest_digest)
            .expect("get")
            .is_none()
    );
}
