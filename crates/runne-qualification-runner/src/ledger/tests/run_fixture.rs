use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use runne_native_qualification::{
    PendingQualificationRunBootstrapProof, QualificationRunBootstrapExpectation,
    QualificationRunBootstrapVerifier, VerifiedQualificationRunBootstrapProof,
};
use serde::Serialize;

#[derive(Clone, Serialize)]
struct Proof {
    schema_version: &'static str,
    context_id: String,
    challenge: String,
    candidate_sha256: String,
    raw_v3_tuple_sha256: String,
    source_revision: String,
    workflow_run_id: &'static str,
    namespace_sha256: String,
    manifest_sha256: String,
    profile_sha256: String,
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
    nonce: String,
}

pub fn proof(ids: [u8; 2], manifest: u8, profile: u8) -> VerifiedQualificationRunBootstrapProof {
    proof_with_window(ids, manifest, profile, 300)
}

pub fn proof_with_window(
    ids: [u8; 2],
    manifest: u8,
    profile: u8,
    window: u64,
) -> VerifiedQualificationRunBootstrapProof {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = SigningKey::from_bytes(&[0x22; 32]);
    let wire = Proof {
        schema_version: "runne/macos-xpc-dpk-run-bootstrap/v1",
        context_id: hex::encode([ids[0]; 32]),
        challenge: hex::encode([0xee; 32]),
        candidate_sha256: hex::encode([0xaa; 32]),
        raw_v3_tuple_sha256: hex::encode([0xbb; 32]),
        source_revision: hex::encode([0xcc; 20]),
        workflow_run_id: "run-42",
        namespace_sha256: hex::encode([0xdd; 32]),
        manifest_sha256: hex::encode([manifest; 32]),
        profile_sha256: hex::encode([profile; 32]),
        issued_at: now,
        expires_at: now + window,
        run_not_after: now + 3600,
        nonce: URL_SAFE_NO_PAD.encode([ids[1]; 32]),
    };
    let bytes = super::fixture::sign(wire, &key, b"runne/macos-xpc-dpk-run-bootstrap/v1\0");
    let expected = QualificationRunBootstrapExpectation::new(
        [0xaa; 32],
        [0xbb; 32],
        [0xcc; 20],
        "run-42",
        [0xdd; 32],
        [manifest; 32],
        [profile; 32],
        [ids[0]; 32],
        [ids[1]; 32],
        [0xee; 32],
        now,
        now + window,
        now + 3600,
        3600,
    )
    .unwrap();
    QualificationRunBootstrapVerifier::test_only_from_verifying_key(key.verifying_key())
        .verify_and_consume(
            PendingQualificationRunBootstrapProof::from_signed_bytes(bytes).unwrap(),
            &expected,
            now,
        )
        .expect("verified signed run proof")
}
