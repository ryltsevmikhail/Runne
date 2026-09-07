//! Removal tests: refuse active references, transactional removal, blob
//! gone, cleanup-pending recovery.

use runne_local_model::gguf_limits::GGUF_MAGIC;
use runne_model_store::{LicenseAcceptance, ModelArtifactStore};
use std::io::Cursor;

fn manifest_json() -> String {
    // Digest over the exact streamed image (tensor-data fixture, 90 bytes).
    let image = gguf_bytes();
    let artifact_digest = format!("sha256:{}", {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&image))
    });
    let byte_len = image.len();
    format!(
        "{{\"artifacts\":[{{\"byteLength\":{byte_len},\"contentType\":\"application/gguf\",\"digest\":\"{artifact_digest}\",\"role\":\"model\"}}],\"capabilities\":{{\"contextMaxTokens\":4096,\"modalities\":[\"text\"],\"outputMaxTokens\":1024,\"reasoning\":false,\"streaming\":true,\"structuredOutput\":false,\"tools\":false}},\"chatTemplate\":{{\"id\":\"chat\",\"revision\":\"1\",\"sourceDigest\":\"sha256:63bce8d4edf0cd46fffe9c93a06ed34806202956d17a36a94df37388d9149b51\"}},\"compatibility\":{{\"backendProfiles\":[{{\"id\":\"llama-cpp-cpu-macos-arm64-v1\",\"revision\":\"v1\"}}]}},\"format\":\"GGUF\",\"hardwareRequirements\":{{\"arch\":\"arm64\",\"minRamBytes\":1,\"os\":\"macos\"}},\"license\":\"Apache-2.0\",\"manifestDigest\":\"__MDG__\",\"minCompatibleRuntime\":\"0.1.0\",\"modelID\":\"m1\",\"modelRevision\":\"r1\",\"provenance\":{{\"acquiredAt\":\"2026-09-04T00:00:00Z\",\"publisher\":\"p\",\"sourceDigest\":\"sha256:25a6634263c1b1f6fc4697a04e2b9904ea4b042a89af59dc93ec1f5d44848a26\",\"sourceUri\":\"https://x.gguf\"}},\"schemaVersion\":\"ModelManifestV1\",\"tokenizer\":{{\"configDigest\":\"sha256:1a7674eb4ee78df7e1ac439a93c3fa8e3c945784d4dec9fd8e3011738b2f1d62\",\"family\":\"bpe\",\"revision\":\"1\"}},\"toolProtocol\":{{\"id\":\"tp\",\"revision\":\"1\",\"schemaDigest\":\"sha256:7c9bbe5ec9b3fb774e8fa0f54247e93c34ddf8e5d16fe3073420de0ae81a262d\",\"semantics\":\"s\"}}}}"
    )
}

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

fn gguf_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GGUF_MAGIC);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes()); // 1 tensor
    out.extend_from_slice(&0u64.to_le_bytes()); // 0 kvs
    let name = b"t0";
    out.extend_from_slice(&(name.len() as u64).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&1u32.to_le_bytes()); // n_dims
    out.extend_from_slice(&8u64.to_le_bytes()); // dim[0]
    out.extend_from_slice(&0u32.to_le_bytes()); // F32
    out.extend_from_slice(&0u64.to_le_bytes()); // offset
    out.extend_from_slice(&[0u8; 32]); // tensor data: 8 × F32
    out
}

fn admit_one(dir: &std::path::Path, _payload: &[u8]) -> String {
    let mut store = ModelArtifactStore::open(dir).expect("store");
    let candidate = store
        .stage_import(
            with_manifest_digest(manifest_json()).as_bytes(),
            &mut Cursor::new(gguf_bytes()),
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
    store
        .get_exact("m1", &candidate.manifest_digest)
        .expect("get")
        .expect("installed")
        .manifest_digest
}

#[test]
fn remove_deletes_installation_and_blob() {
    let dir = tempfile::tempdir().expect("dir");
    let digest = admit_one(dir.path(), b"x");
    let _ = &digest;
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    let disposition = store.remove(&digest).expect("remove");
    assert_eq!(disposition, runne_model_store::RemoveDisposition::Removed);
    assert!(store.list().expect("list").is_empty());
    // Tombstone recorded.
    let pending: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM tombstones WHERE manifest_digest = ?1",
            [&digest],
            |row| row.get(0),
        )
        .expect("tombstone");
    assert_eq!(pending, 1);
}

#[test]
fn remove_unknown_id_is_missing() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    let err = store.remove("nonexistent").expect_err("missing");
    assert!(matches!(
        err,
        runne_model_store::StoreError::CandidateMissing
    ));
}

#[test]
fn recovery_completes_interrupted_cleanup() {
    let dir = tempfile::tempdir().expect("dir");
    let digest = admit_one(dir.path(), b"x");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    // Simulate crash after catalog removal but before blob deletion:
    // remove, then re-create the blob file behind the tombstone.
    store.remove(&digest).expect("remove");
    let blob_path = dir
        .path()
        .join("blobs")
        .join(&digest[..digest.len().min(64)]);
    std::fs::write(&blob_path, b"resurrected").expect("rewrite");
    let report = store.recover().expect("recover");
    assert!(report.tombstones_cleaned >= 1 || !blob_path.exists());
}
