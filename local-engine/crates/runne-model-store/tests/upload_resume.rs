//! Upload resume tests: exact-offset enforcement, prefix revalidation,
//! restart resume, cancel.

use runne_local_model::gguf_limits::GGUF_MAGIC;
use runne_model_store::ModelArtifactStore;

fn manifest_json() -> String {
    let artifact_digest = format!("sha256:{}", {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(gguf_bytes().as_slice()))
    });
    format!(
        "{{\"artifacts\":[{{\"byteLength\":24,\"contentType\":\"application/gguf\",\"digest\":\"{artifact_digest}\",\"role\":\"model\"}}],\"capabilities\":{{\"contextMaxTokens\":4096,\"modalities\":[\"text\"],\"outputMaxTokens\":1024,\"reasoning\":false,\"streaming\":true,\"structuredOutput\":false,\"tools\":false}},\"chatTemplate\":{{\"id\":\"chat\",\"revision\":\"1\",\"sourceDigest\":\"sha256:63bce8d4edf0cd46fffe9c93a06ed34806202956d17a36a94df37388d9149b51\"}},\"compatibility\":{{\"backendProfiles\":[{{\"id\":\"llama-cpp-cpu-macos-arm64-v1\",\"revision\":\"v1\"}}]}},\"format\":\"GGUF\",\"hardwareRequirements\":{{\"arch\":\"arm64\",\"minRamBytes\":1,\"os\":\"macos\"}},\"license\":\"Apache-2.0\",\"manifestDigest\":\"__MDG__\",\"minCompatibleRuntime\":\"0.1.0\",\"modelID\":\"m1\",\"modelRevision\":\"r1\",\"provenance\":{{\"acquiredAt\":\"2026-09-04T00:00:00Z\",\"publisher\":\"p\",\"sourceDigest\":\"sha256:25a6634263c1b1f6fc4697a04e2b9904ea4b042a89af59dc93ec1f5d44848a26\",\"sourceUri\":\"https://x/m.gguf\"}},\"schemaVersion\":\"ModelManifestV1\",\"tokenizer\":{{\"configDigest\":\"sha256:1a7674eb4ee78df7e1ac439a93c3fa8e3c945784d4dec9fd8e3011738b2f1d62\",\"family\":\"bpe\",\"revision\":\"1\"}},\"toolProtocol\":{{\"id\":\"tp\",\"revision\":\"1\",\"schemaDigest\":\"sha256:7c9bbe5ec9b3fb774e8fa0f54247e93c34ddf8e5d16fe3073420de0ae81a262d\",\"semantics\":\"s\"}}}}"
    )
}

fn gguf_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GGUF_MAGIC);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

fn open(dir: &std::path::Path) -> ModelArtifactStore {
    ModelArtifactStore::open(dir).expect("store")
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

#[test]
fn exact_offset_enforced() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = open(dir.path());
    let mut session = store
        .begin_stage(with_manifest_digest(manifest_json()).as_bytes(), 24, 600)
        .expect("begin");
    let err = store
        .append_stage(&mut session, 1, b"x")
        .expect_err("wrong offset");
    assert!(matches!(
        err,
        runne_model_store::StoreError::OffsetMismatch { expected: 0 }
    ));
}

#[test]
fn chunked_upload_finalizes_to_candidate() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = open(dir.path());
    let mut session = store
        .begin_stage(with_manifest_digest(manifest_json()).as_bytes(), 24, 600)
        .expect("begin");
    let data = gguf_bytes();
    let mut off = 0usize;
    for chunk in data.chunks(8) {
        off = store
            .append_stage(&mut session, off as u64, chunk)
            .expect("append") as usize;
    }
    assert_eq!(off, 24);
    let candidate = store.finalize_stage(&session).expect("finalize");
    assert_eq!(candidate.model_id, "m1");
}

#[test]
fn cancel_drops_session() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = open(dir.path());
    let mut session = store
        .begin_stage(with_manifest_digest(manifest_json()).as_bytes(), 24, 600)
        .expect("begin");
    store
        .append_stage(&mut session, 0, &gguf_bytes()[..16])
        .expect("append");
    store.cancel_stage(&session).expect("cancel");
    let err = store
        .append_stage(&mut session, 16, &gguf_bytes()[16..])
        .expect_err("cancelled");
    assert!(matches!(err, runne_model_store::StoreError::SessionMissing));
}

#[test]
fn restart_resume_verifies_prefix() {
    let dir = tempfile::tempdir().expect("dir");
    {
        let mut store = open(dir.path());
        let mut session = store
            .begin_stage(with_manifest_digest(manifest_json()).as_bytes(), 24, 600)
            .expect("begin");
        store
            .append_stage(&mut session, 0, &gguf_bytes()[..16])
            .expect("append");
        // "crash": store dropped here.
    }
    {
        let mut store = open(dir.path());
        let mut session = store
            .begin_stage(with_manifest_digest(manifest_json()).as_bytes(), 24, 600)
            .expect("re-begin");
        // Prefix revalidation: committed offset is 16 from the first store;
        // resume continues from there (never from zero).
        let mut off = session.committed_offset as usize;
        assert_eq!(off, 16);
        let data = gguf_bytes();
        for chunk in data[off..].chunks(8) {
            off = store
                .append_stage(&mut session, off as u64, chunk)
                .expect("append") as usize;
        }
        assert_eq!(off, 24);
    }
}
