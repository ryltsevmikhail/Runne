use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, SigningKey};

use crate::issuer::{UnsignedBootstrap, sign};

#[test]
fn issued_proof_matches_closed_verifier_wire_and_bootstrap_signature_domain() {
    let input = UnsignedBootstrap {
        schema_version: "runne/macos-xpc-dpk-run-bootstrap/v1",
        context_id: "11".repeat(32),
        challenge: "22".repeat(32),
        candidate_sha256: "33".repeat(32),
        raw_v3_tuple_sha256: "44".repeat(32),
        source_revision: "55".repeat(20),
        workflow_run_id: "run-42".into(),
        namespace_sha256: "66".repeat(32),
        manifest_sha256: "77".repeat(32),
        profile_sha256: "88".repeat(32),
        issued_at: 100,
        expires_at: 200,
        run_not_after: 300,
        nonce: URL_SAFE_NO_PAD.encode([0x99; 32]),
    };
    let key = SigningKey::from_bytes(&[0x23; 32]);
    let proof = sign(&input, &key).unwrap();
    let wire: serde_json::Value = serde_json::from_slice(&proof).unwrap();
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(wire["signature"]["value"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature = Signature::from_bytes(&signature);
    let unsigned = serde_json::to_vec(&input).unwrap();
    let mut payload = b"runne/macos-xpc-dpk-run-bootstrap/v1\0".to_vec();
    payload.extend_from_slice(&unsigned);
    key.verifying_key()
        .verify_strict(&payload, &signature)
        .unwrap();
    assert!(
        key.verifying_key()
            .verify_strict(&unsigned, &signature)
            .is_err()
    );
    payload[0] ^= 1;
    assert!(
        key.verifying_key()
            .verify_strict(&payload, &signature)
            .is_err()
    );
    assert_eq!(wire["challenge"], input.challenge);
    assert_eq!(wire["run_not_after"], 300);
    assert!(
        runne_native_qualification::PendingQualificationRunBootstrapProof::from_signed_bytes(proof)
            .is_ok()
    );
}
