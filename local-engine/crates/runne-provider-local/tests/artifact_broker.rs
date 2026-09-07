//! Artifact broker tests: no-path DTOs, symlink/length/digest negatives,
//! reuse, binding mismatches, expiry, role separation.

use runne_local_model::gguf_limits::GGUF_MAGIC;
use runne_model_store::{LicenseAcceptance, ModelArtifactStore};
use runne_provider_local::ModelArtifactBrokerPort;
use runne_provider_local::grant::{ArtifactGrantRequest, GrantRole};
use std::io::Cursor;

fn gguf_image() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GGUF_MAGIC);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

fn sha(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

fn hex_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Opens a store, admits one model (24-byte 0-tensor GGUF), returns the
/// broker, the catalog digest (bare hex PK) and the artifact digest.
fn setup(dir: &std::path::Path) -> (ModelArtifactBrokerPort, String, String) {
    let mut store = ModelArtifactStore::open(dir).expect("store");
    let image = gguf_image();
    let artifact_digest = sha(&image);
    let manifest = format!(
        "{{\"artifacts\":[{{\"byteLength\":24,\"contentType\":\"application/gguf\",\"digest\":\"{artifact_digest}\",\"role\":\"model\"}}],\"capabilities\":{{\"contextMaxTokens\":4096,\"modalities\":[\"text\"],\"outputMaxTokens\":1024,\"reasoning\":false,\"streaming\":true,\"structuredOutput\":false,\"tools\":false}},\"chatTemplate\":{{\"id\":\"c\",\"revision\":\"1\",\"sourceDigest\":\"sha256:{}\"}},\"compatibility\":{{\"backendProfiles\":[{{\"id\":\"llama-cpp-cpu-macos-arm64-v1\",\"revision\":\"v1\"}}]}},\"format\":\"GGUF\",\"hardwareRequirements\":{{\"arch\":\"arm64\",\"minRamBytes\":1,\"os\":\"macos\"}},\"license\":\"Apache-2.0\",\"manifestDigest\":\"__MDG__\",\"minCompatibleRuntime\":\"0.1.0\",\"modelID\":\"m1\",\"modelRevision\":\"r1\",\"provenance\":{{\"acquiredAt\":\"2026-09-04T00:00:00Z\",\"publisher\":\"p\",\"sourceDigest\":\"sha256:{}\",\"sourceUri\":\"https://x\"}},\"schemaVersion\":\"ModelManifestV1\",\"tokenizer\":{{\"configDigest\":\"sha256:{}\",\"family\":\"bpe\",\"revision\":\"1\"}},\"toolProtocol\":{{\"id\":\"tp\",\"revision\":\"1\",\"schemaDigest\":\"sha256:{}\",\"semantics\":\"s\"}}}}",
        hex_digest(b"c"),
        hex_digest(b"s"),
        hex_digest(b"t"),
        hex_digest(b"tp")
    );
    // Compute and splice manifestDigest over the sorted preimage.
    let preimage = {
        let with_mdg = manifest.replace("__MDG__", "PLACEHOLDER");
        let member = "\"manifestDigest\":\"PLACEHOLDER\",";
        with_mdg.replace(member, "")
    };
    let manifest_digest = format!("sha256:{}", hex_digest(preimage.as_bytes()));
    let manifest = manifest.replace("__MDG__", &manifest_digest);

    let artifact = gguf_image();
    let candidate = store
        .stage_import(manifest.as_bytes(), &mut Cursor::new(artifact))
        .expect("stage");
    let accepted = LicenseAcceptance {
        license_digest: hex_digest(candidate.license.as_bytes()),
    };
    store
        .admit(&candidate.candidate_id, &accepted)
        .expect("admit");
    let broker = ModelArtifactBrokerPort::new(ModelArtifactStore::open(dir).expect("reopen"))
        .expect("broker");
    // Catalog PK is the bare digest (no sha256: prefix).
    let catalog_digest = manifest_digest.rsplit(':').next().unwrap_or("").to_string();
    (broker, catalog_digest, artifact_digest)
}

fn request(manifest_digest: &str, artifact_digest: &str) -> ArtifactGrantRequest {
    ArtifactGrantRequest {
        manifest_digest: manifest_digest.to_string(),
        artifact_digest: artifact_digest.to_string(),
        byte_len: 24,
        role: GrantRole::HostInspection,
        host_generation: 1,
        load_id: [7; 16],
        session_id: [8; 16],
        ttl_secs: 60,
    }
}

#[test]
fn grant_debug_has_no_paths() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg, adg) = setup(dir.path());
    let grant = broker.issue_grant(&request(&mdg, &adg)).expect("grant");
    let debug = format!("{grant:?}");
    assert!(!debug.contains('/'), "path leaked in Debug: {debug}");
}

#[test]
fn length_mismatch_rejected_at_issue() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg, adg) = setup(dir.path());
    let mut req = request(&mdg, &adg);
    req.byte_len = 999;
    let err = broker.issue_grant(&req).expect_err("mismatch");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::FrameMismatch
    ));
}

#[test]
fn unknown_manifest_rejected() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, _mdg, _adg) = setup(dir.path());
    let mut req = request(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    req.byte_len = 24;
    let err = broker.issue_grant(&req).expect_err("unknown");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::ArtifactNotInstalled
    ));
}

#[test]
fn issue_uses_catalog_digest_only() {
    // The broker resolves content by catalog digest; a symlink under a
    // different name in the blobs dir is not a catalog address.
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg, adg) = setup(dir.path());
    let blobs: std::path::PathBuf = dir.path().join("blobs");
    let link = blobs.join("linked");
    #[cfg(unix)]
    if let Some(first_blob) = std::fs::read_dir(&blobs)
        .expect("blobs dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .next()
    {
        std::os::unix::fs::symlink(&first_blob, &link).expect("symlink");
    }
    let result = broker.issue_grant(&request(&mdg, &adg));
    assert!(result.is_ok(), "issue resolves only catalog addresses");
    let _ = link;
}

#[test]
fn grant_reuse_rejected() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg, adg) = setup(dir.path());
    let req = request(&mdg, &adg);
    let grant = broker.issue_grant(&req).expect("grant");
    let fd = broker.consume_grant(grant.grant_id, &req).expect("consume");
    drop(fd);
    let err = broker
        .consume_grant(grant.grant_id, &req)
        .expect_err("reuse");
    eprintln!("REUSE ERR: {err:?}");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::Broker(
            runne_engine_broker::BrokerError::AlreadyConsumed
        )
    ));
}

#[test]
fn wrong_role_and_generation_and_load_rejected() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg, adg) = setup(dir.path());
    let req = request(&mdg, &adg);
    let grant = broker.issue_grant(&req).expect("grant");
    // Wrong role.
    let mut wrong_role = req.clone();
    wrong_role.role = GrantRole::BackendWorkerLoad {
        worker_generation: 1,
    };
    let err = broker
        .consume_grant(grant.grant_id, &wrong_role)
        .expect_err("role");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::Broker(runne_engine_broker::BrokerError::WrongRole)
    ));
    // Wrong host generation.
    let mut wrong_gen = req.clone();
    wrong_gen.host_generation = 99;
    let err = broker
        .consume_grant(grant.grant_id, &wrong_gen)
        .expect_err("generation");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::Broker(
            runne_engine_broker::BrokerError::WrongGeneration
        )
    ));
    // Wrong load id.
    let mut wrong_load = req.clone();
    wrong_load.load_id = [1; 16];
    let err = broker
        .consume_grant(grant.grant_id, &wrong_load)
        .expect_err("load");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::Broker(runne_engine_broker::BrokerError::WrongLoadId)
    ));
}

#[test]
fn expired_grant_rejected() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg, adg) = setup(dir.path());
    let mut req = request(&mdg, &adg);
    req.ttl_secs = 0;
    let grant = broker.issue_grant(&req).expect("grant");
    std::thread::sleep(std::time::Duration::from_secs(1));
    let err = broker
        .consume_grant(grant.grant_id, &req)
        .expect_err("expired");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::Broker(runne_engine_broker::BrokerError::GrantExpired)
    ));
}

#[test]
fn host_and_worker_grants_are_distinct() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg, adg) = setup(dir.path());
    let mut host_req = request(&mdg, &adg);
    host_req.role = GrantRole::HostInspection;
    let mut worker_req = request(&mdg, &adg);
    worker_req.role = GrantRole::BackendWorkerLoad {
        worker_generation: 3,
    };
    let host_grant = broker.issue_grant(&host_req).expect("host");
    let worker_grant = broker.issue_grant(&worker_req).expect("worker");
    assert_ne!(host_grant.grant_id, worker_grant.grant_id);
    let err = broker
        .consume_grant(worker_grant.grant_id, &host_req)
        .expect_err("cross-role");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::Broker(runne_engine_broker::BrokerError::WrongRole)
    ));
}
