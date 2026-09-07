//! Grant lifecycle tests: issued → transferred → consumed →
//! recipient_closed per role; pre-transfer revoke; post-transfer
//! termination_required; SCM_RIGHTS roundtrip with CLOEXEC verification.

use runne_local_model::gguf_limits::GGUF_MAGIC;
use runne_model_store::{LicenseAcceptance, ModelArtifactStore};
use runne_provider_local::grant::{ArtifactGrantRequest, GrantRole};
use runne_provider_local::{ModelArtifactBrokerPort, ProviderError, artifact_transport};
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

fn setup(dir: &std::path::Path) -> (ModelArtifactBrokerPort, String) {
    let mut store = ModelArtifactStore::open(dir).expect("store");
    let image = gguf_image();
    let digest = sha(&image);
    let manifest = format!(
        "{{\"artifacts\":[{{\"byteLength\":24,\"contentType\":\"application/gguf\",\"digest\":\"{digest}\",\"role\":\"model\"}}],\"capabilities\":{{\"contextMaxTokens\":4096,\"modalities\":[\"text\"],\"outputMaxTokens\":1024,\"reasoning\":false,\"streaming\":true,\"structuredOutput\":false,\"tools\":false}},\"chatTemplate\":{{\"id\":\"c\",\"revision\":\"1\",\"sourceDigest\":\"sha256:{}\"}},\"compatibility\":{{\"backendProfiles\":[{{\"id\":\"llama-cpp-cpu-macos-arm64-v1\",\"revision\":\"v1\"}}]}},\"format\":\"GGUF\",\"hardwareRequirements\":{{\"arch\":\"arm64\",\"minRamBytes\":1,\"os\":\"macos\"}},\"license\":\"Apache-2.0\",\"manifestDigest\":\"__MDG__\",\"minCompatibleRuntime\":\"0.1.0\",\"modelID\":\"m1\",\"modelRevision\":\"r1\",\"provenance\":{{\"acquiredAt\":\"2026-09-04T00:00:00Z\",\"publisher\":\"p\",\"sourceDigest\":\"sha256:{}\",\"sourceUri\":\"https://x\"}},\"schemaVersion\":\"ModelManifestV1\",\"tokenizer\":{{\"configDigest\":\"sha256:{}\",\"family\":\"bpe\",\"revision\":\"1\"}},\"toolProtocol\":{{\"id\":\"tp\",\"revision\":\"1\",\"schemaDigest\":\"sha256:{}\",\"semantics\":\"s\"}}}}",
        hex_digest(b"c"),
        hex_digest(b"s"),
        hex_digest(b"t"),
        hex_digest(b"tp")
    );
    let preimage = manifest.replace("\"manifestDigest\":\"__MDG__\",", "");
    let manifest_digest = format!("sha256:{}", hex_digest(preimage.as_bytes()));
    let manifest = manifest.replace("__MDG__", &manifest_digest);
    let candidate = store
        .stage_import(manifest.as_bytes(), &mut Cursor::new(image))
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
    (broker, catalog_digest)
}

fn hex_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

fn request(manifest_digest: &str, role: GrantRole) -> ArtifactGrantRequest {
    ArtifactGrantRequest {
        manifest_digest: manifest_digest.to_string(),
        artifact_digest: format!("sha256:{}", hex_digest(gguf_image().as_slice())),
        byte_len: 24,
        role,
        host_generation: 1,
        load_id: [7; 16],
        session_id: [8; 16],
        ttl_secs: 60,
    }
}

#[test]
fn host_lifecycle_issued_transferred_consumed_closed() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg) = setup(dir.path());
    let req = request(&mdg, GrantRole::HostInspection);
    let grant = broker.issue_grant(&req).expect("issue");
    let fd = broker
        .consume_grant(grant.grant_id, &req)
        .expect("transfer");
    drop(fd); // recipient closes after use
    let state = broker
        .mark_consumed(grant.grant_id, "host:read")
        .expect("consumed");
    assert_eq!(
        state,
        runne_engine_broker::broker::artifact::GrantState::Consumed
    );
    let closed = broker
        .recipient_closed(grant.grant_id, "host:read")
        .expect("closed");
    assert_eq!(
        closed,
        runne_engine_broker::broker::artifact::GrantState::RecipientClosed
    );
}

#[test]
fn worker_lifecycle_requires_worker_evidence() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg) = setup(dir.path());
    let req = request(
        &mdg,
        GrantRole::BackendWorkerLoad {
            worker_generation: 3,
        },
    );
    let grant = broker.issue_grant(&req).expect("issue");
    let fd = broker.consume_grant(grant.grant_id, &req).expect("xfer");
    drop(fd);
    // Host-style evidence is insufficient for a worker grant.
    let err = broker
        .mark_consumed(grant.grant_id, "host:closed")
        .expect_err("host evidence");
    assert!(matches!(
        err,
        ProviderError::Broker(runne_engine_broker::BrokerError::EvidenceInsufficient)
    ));
    let state = broker
        .mark_consumed(grant.grant_id, "worker:3")
        .expect("consumed");
    assert_eq!(
        state,
        runne_engine_broker::broker::artifact::GrantState::Consumed
    );
}

#[test]
fn pre_transfer_revocation_blocks_consumption() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg) = setup(dir.path());
    let req = request(&mdg, GrantRole::HostInspection);
    let grant = broker.issue_grant(&req).expect("issue");
    let disposition = broker.revoke_grant(grant.grant_id).expect("revoke");
    assert_eq!(
        disposition,
        runne_engine_broker::broker::artifact::RevokeDisposition::Revoked
    );
    let err = broker
        .consume_grant(grant.grant_id, &req)
        .expect_err("revoked");
    assert!(matches!(
        err,
        ProviderError::Broker(runne_engine_broker::BrokerError::AlreadyRevoked)
    ));
}

#[test]
fn post_transfer_revocation_requires_termination() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg) = setup(dir.path());
    let req = request(&mdg, GrantRole::HostInspection);
    let grant = broker.issue_grant(&req).expect("issue");
    let fd = broker.consume_grant(grant.grant_id, &req).expect("xfer");
    drop(fd);
    let disposition = broker.revoke_grant(grant.grant_id).expect("revoke");
    assert_eq!(
        disposition,
        runne_engine_broker::broker::artifact::RevokeDisposition::TerminationRequired
    );
    // Consumption after termination-required stays impossible.
    let err = broker
        .consume_grant(grant.grant_id, &req)
        .expect_err("terminated");
    assert!(matches!(
        err,
        ProviderError::Broker(runne_engine_broker::BrokerError::AlreadyConsumed)
    ));
}

#[test]
fn scm_rights_roundtrip_transfers_content() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg) = setup(dir.path());
    let req = request(&mdg, GrantRole::HostInspection);
    let grant = broker.issue_grant(&req).expect("issue");
    let (client_sock, host_sock) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    // Broker sends the issued descriptor to the "host".
    let sent_fd = broker.issued_descriptor(grant.grant_id).expect("fd");
    runne_engine_broker::broker::artifact_unix::send_one(&client_sock, sent_fd).expect("send");
    let received = runne_engine_broker::broker::artifact_unix::recv_one(&host_sock).expect("recv");
    // CLOEXEC set on the received descriptor.
    let flags = rustix::io::fcntl_getfd(&received).expect("getfd");
    assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    // Content through the received fd matches the image.
    let mut buf = vec![0u8; 24];
    rustix::fs::seek(&received, rustix::fs::SeekFrom::Start(0)).expect("seek");
    rustix::io::read(&received, &mut buf).expect("read");
    assert_eq!(buf, gguf_image());
}

#[test]
fn frame_binding_rejects_zero_extra_and_mismatched() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut broker, mdg) = setup(dir.path());
    let req = request(&mdg, GrantRole::HostInspection);
    let grant = broker.issue_grant(&req).expect("issue");
    let (pinned, _pinned_len) = broker.grant_identity(grant.grant_id).expect("identity");
    let claim = artifact_transport::FrameClaim {
        frame_type: "load_model",
        artifact_digest: &grant.artifact_digest,
        byte_len: grant.byte_len,
    };
    // Zero fds.
    let (sock_a, sock_b) = std::os::unix::net::UnixStream::pair().expect("pair");
    let err = artifact_transport::bind_frame_fd(Vec::new(), &sock_a, &claim, &grant, &pinned)
        .expect_err("zero fds");
    assert!(matches!(err, ProviderError::FdMissing));
    drop(sock_b);
    // Wrong digest claim.
    let wrong_claim = artifact_transport::FrameClaim {
        frame_type: "load_model",
        artifact_digest: "sha256:deadbeef",
        byte_len: grant.byte_len,
    };
    let err = artifact_transport::bind_frame_fd(Vec::new(), &sock_a, &wrong_claim, &grant, &pinned)
        .expect_err("wrong digest claim");
    assert!(matches!(err, ProviderError::FdMissing));
    // Mismatched byte length.
    let wrong_len = artifact_transport::FrameClaim {
        frame_type: "load_model",
        artifact_digest: &grant.artifact_digest,
        byte_len: 99,
    };
    let err = artifact_transport::bind_frame_fd(Vec::new(), &sock_a, &wrong_len, &grant, &pinned)
        .expect_err("wrong len");
    assert!(matches!(err, ProviderError::FdMissing));
    drop(sock_a);
}
