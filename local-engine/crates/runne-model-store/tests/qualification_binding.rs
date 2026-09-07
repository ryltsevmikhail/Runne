//! Qualification-matrix binding (Plan Task 22): the admission record
//! pins the matrix revision; a revision bump on the same digest is an
//! AdmissionConflict (traceable via explicit commit); an unqualified
//! install carries an empty revision and cannot back a capability
//! claim.

use runne_local_model::gguf_limits::GGUF_MAGIC;
use runne_model_store::{LicenseAcceptance, MatrixBinding, ModelArtifactStore};
use std::io::Cursor;

fn gguf() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GGUF_MAGIC);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

fn manifest_with_digest(_image: &[u8], artifact_digest: &str) -> String {
    let h = |data: &[u8]| -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(data))
    };
    let manifest = format!(
        "{{\"artifacts\":[{{\"byteLength\":24,\"contentType\":\"application/gguf\",\"digest\":\"{artifact_digest}\",\"role\":\"model\"}}],\"capabilities\":{{\"contextMaxTokens\":4096,\"modalities\":[\"text\"],\"outputMaxTokens\":1024,\"reasoning\":false,\"streaming\":true,\"structuredOutput\":false,\"tools\":false}},\"chatTemplate\":{{\"id\":\"c\",\"revision\":\"1\",\"sourceDigest\":\"sha256:{}\"}},\"compatibility\":{{\"backendProfiles\":[{{\"id\":\"llama-cpp-cpu-macos-arm64-v1\",\"revision\":\"v1\"}}]}},\"format\":\"GGUF\",\"hardwareRequirements\":{{\"arch\":\"arm64\",\"minRamBytes\":1,\"os\":\"macos\"}},\"license\":\"Apache-2.0\",\"manifestDigest\":\"__MDG__\",\"minCompatibleRuntime\":\"0.1.0\",\"modelID\":\"m1\",\"modelRevision\":\"r1\",\"provenance\":{{\"acquiredAt\":\"2026-09-05T00:00:00Z\",\"publisher\":\"p\",\"sourceDigest\":\"sha256:{}\",\"sourceUri\":\"https://x\"}},\"schemaVersion\":\"ModelManifestV1\",\"tokenizer\":{{\"configDigest\":\"sha256:{}\",\"family\":\"bpe\",\"revision\":\"1\"}},\"toolProtocol\":{{\"id\":\"tp\",\"revision\":\"1\",\"schemaDigest\":\"sha256:{}\",\"semantics\":\"s\"}}}}",
        h(b"c"),
        h(b"s"),
        h(b"t"),
        h(b"tp")
    );
    let preimage = manifest.replace("\"manifestDigest\":\"__MDG__\",", "");
    manifest.replace("__MDG__", &format!("sha256:{}", h(preimage.as_bytes())))
}

#[test]
fn qualified_admit_pins_matrix_revision() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    let image = gguf();
    use sha2::Digest as _;
    let artifact_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&image)));
    let manifest = manifest_with_digest(&image, &artifact_digest);
    let candidate = store
        .stage_import(manifest.as_bytes(), &mut Cursor::new(image.clone()))
        .expect("stage");
    let acceptance = LicenseAcceptance {
        license_digest: hex::encode(sha2::Sha256::digest(candidate.license.as_bytes())),
    };
    let binding = MatrixBinding {
        revision: "2026-09-05-r1",
        entry_id: "entry-llama-q4-mini",
        evidence_ref: "docs/golden/local-engine/evidence/entry-llama-q4-mini.md",
    };
    let installed = store
        .admit_qualified(&candidate.candidate_id, &acceptance, &binding)
        .expect("qualified admit");
    assert_eq!(installed.matrix_revision, "2026-09-05-r1");
    let read = store
        .get_exact_by_digest(&installed.manifest_digest)
        .expect("read")
        .expect("present");
    assert_eq!(read.matrix_revision, "2026-09-05-r1");
}

#[test]
fn revision_bump_on_same_digest_conflicts() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    let image = gguf();
    use sha2::Digest as _;
    let artifact_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&image)));
    let manifest = manifest_with_digest(&image, &artifact_digest);
    let candidate = store
        .stage_import(manifest.as_bytes(), &mut Cursor::new(image))
        .expect("stage");
    let acceptance = LicenseAcceptance {
        license_digest: hex::encode(sha2::Sha256::digest(candidate.license.as_bytes())),
    };
    let b1 = MatrixBinding {
        revision: "2026-09-05-r1",
        entry_id: "e1",
        evidence_ref: "evidence/e1.md",
    };
    store
        .admit_qualified(&candidate.candidate_id, &acceptance, &b1)
        .expect("first");
    // A bumped revision cannot overwrite the pinned record: the
    // install identity is immutable; the bump is a new explicit commit.
    let b2 = MatrixBinding {
        revision: "2026-10-01-r2",
        ..b1
    };
    let err = store
        .admit_qualified(&candidate.candidate_id, &acceptance, &b2)
        .expect_err("immutable");
    assert!(matches!(
        err,
        runne_model_store::StoreError::AdmissionConflict
    ));
}

#[test]
fn unqualified_admit_carries_empty_revision() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    let image = gguf();
    use sha2::Digest as _;
    let artifact_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&image)));
    let manifest = manifest_with_digest(&image, &artifact_digest);
    let candidate = store
        .stage_import(manifest.as_bytes(), &mut Cursor::new(image))
        .expect("stage");
    let acceptance = LicenseAcceptance {
        license_digest: hex::encode(sha2::Sha256::digest(candidate.license.as_bytes())),
    };
    let installed = store
        .admit(&candidate.candidate_id, &acceptance)
        .expect("admit");
    assert_eq!(installed.matrix_revision, "", "unqualified");
}

#[test]
fn empty_binding_fields_reject() {
    let dir = tempfile::tempdir().expect("dir");
    let mut store = ModelArtifactStore::open(dir.path()).expect("store");
    let image = gguf();
    use sha2::Digest as _;
    let artifact_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&image)));
    let manifest = manifest_with_digest(&image, &artifact_digest);
    let candidate = store
        .stage_import(manifest.as_bytes(), &mut Cursor::new(image))
        .expect("stage");
    let acceptance = LicenseAcceptance {
        license_digest: hex::encode(sha2::Sha256::digest(candidate.license.as_bytes())),
    };
    let bad = MatrixBinding {
        revision: "2026-09-05-r1",
        entry_id: "e1",
        evidence_ref: "",
    };
    let err = store
        .admit_qualified(&candidate.candidate_id, &acceptance, &bad)
        .expect_err("empty evidence");
    assert!(matches!(err, runne_model_store::StoreError::Schema(_)));
}
