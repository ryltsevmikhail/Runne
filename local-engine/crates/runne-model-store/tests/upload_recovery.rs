//! Upload recovery: startup GC of expired sessions and prefix-mismatch
//! quarantine handling. Crash mid-upload → resume from committed prefix.

use runne_local_model::gguf_limits::GGUF_MAGIC;
use runne_model_store::ModelArtifactStore;

/// 0-tensor GGUF image, exactly 24 bytes (no trailing padding — the
/// parser rejects trailing structural inconsistency).
fn gguf_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GGUF_MAGIC);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

fn manifest_json() -> String {
    let artifact_digest = format!("sha256:{}", {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(gguf_bytes().as_slice()))
    });
    let byte_len = gguf_bytes().len();
    format!(
        "{{\"artifacts\":[{{\"byteLength\":{byte_len},\"contentType\":\"application/gguf\",\"digest\":\"{artifact_digest}\",\"role\":\"model\"}}],\"capabilities\":{{\"contextMaxTokens\":4096,\"modalities\":[\"text\"],\"outputMaxTokens\":1024,\"reasoning\":false,\"streaming\":true,\"structuredOutput\":false,\"tools\":false}},\"chatTemplate\":{{\"id\":\"chat\",\"revision\":\"1\",\"sourceDigest\":\"sha256:63bce8d4edf0cd46fffe9c93a06ed34806202956d17a36a94df37388d9149b51\"}},\"compatibility\":{{\"backendProfiles\":[{{\"id\":\"llama-cpp-cpu-macos-arm64-v1\",\"revision\":\"v1\"}}]}},\"format\":\"GGUF\",\"hardwareRequirements\":{{\"arch\":\"arm64\",\"minRamBytes\":1,\"os\":\"macos\"}},\"license\":\"Apache-2.0\",\"manifestDigest\":\"__MDG__\",\"minCompatibleRuntime\":\"0.1.0\",\"modelID\":\"m1\",\"modelRevision\":\"r1\",\"provenance\":{{\"acquiredAt\":\"2026-09-04T00:00:00Z\",\"publisher\":\"p\",\"sourceDigest\":\"sha256:25a6634263c1b1f6fc4697a04e2b9904ea4b042a89af59dc93ec1f5d44848a26\",\"sourceUri\":\"https://x/m.gguf\"}},\"schemaVersion\":\"ModelManifestV1\",\"tokenizer\":{{\"configDigest\":\"sha256:1a7674eb4ee78df7e1ac439a93c3fa8e3c945784d4dec9fd8e3011738b2f1d62\",\"family\":\"bpe\",\"revision\":\"1\"}},\"toolProtocol\":{{\"id\":\"tp\",\"revision\":\"1\",\"schemaDigest\":\"sha256:7c9bbe5ec9b3fb774e8fa0f54247e93c34ddf8e5d16fe3073420de0ae81a262d\",\"semantics\":\"s\"}}}}"
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

#[test]
fn recovery_reclaims_after_crash() {
    let dir = tempfile::tempdir().expect("dir");
    {
        let mut store = ModelArtifactStore::open(dir.path()).expect("store");
        let mut session = store
            .begin_stage(
                with_manifest_digest(manifest_json()).as_bytes(),
                gguf_bytes().len() as u64,
                600,
            )
            .expect("begin");
        store
            .append_stage(&mut session, 0, &gguf_bytes()[..16])
            .expect("append");
        // "crash": drop without finalize.
    }
    let mut store = ModelArtifactStore::open(dir.path()).expect("reopen");
    let report = store.recover().expect("recover");
    // Session is open and unexpired — recovery must not destroy it; the
    // orphan sweep touches only unreferenced blobs, not quarantine parts.
    assert_eq!(report.expired_sessions, 0);
    // Re-begin resumes from the committed prefix (16 bytes survived).
    let mut session = store
        .begin_stage(
            with_manifest_digest(manifest_json()).as_bytes(),
            gguf_bytes().len() as u64,
            600,
        )
        .expect("re-begin");
    assert_eq!(session.committed_offset, 16);
    let mut off = session.committed_offset as usize;
    for chunk in gguf_bytes()[off..].chunks(8) {
        off = store
            .append_stage(&mut session, off as u64, chunk)
            .expect("append") as usize;
    }
    assert_eq!(off, 24);
    let candidate = store.finalize_stage(&session).expect("finalize");
    // Publication is admission-gated (license acceptance), not finalize-gated.
    let accepted = runne_model_store::LicenseAcceptance {
        license_digest: {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(candidate.license.as_bytes()))
        },
    };
    store
        .admit(&candidate.candidate_id, &accepted)
        .expect("admit");
    assert_eq!(store.list().expect("list").len(), 1);
}
