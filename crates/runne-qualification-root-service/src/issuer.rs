use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{Error, Result};

/// Populated only from the durable armed expectation, never from submitted proof.
#[derive(Serialize)]
pub struct UnsignedBootstrap {
    pub schema_version: &'static str,
    pub context_id: String,
    pub challenge: String,
    pub candidate_sha256: String,
    pub raw_v3_tuple_sha256: String,
    pub source_revision: String,
    pub workflow_run_id: String,
    pub namespace_sha256: String,
    pub manifest_sha256: String,
    pub profile_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub run_not_after: u64,
    pub nonce: String,
}

#[derive(Serialize)]
struct SignedBootstrap<'a> {
    #[serde(flatten)]
    unsigned: &'a UnsignedBootstrap,
    signature: Signature,
}

#[derive(Serialize)]
struct Signature {
    algorithm: &'static str,
    key_id: String,
    value: String,
}

pub fn sign(value: &UnsignedBootstrap, key: &SigningKey) -> Result<Vec<u8>> {
    let mut payload = b"runne/macos-xpc-dpk-run-bootstrap/v1\0".to_vec();
    payload.extend_from_slice(&serde_json::to_vec(value).map_err(|_| Error)?);
    let signature = key.sign(&payload);
    let bytes = serde_json::to_vec(&SignedBootstrap {
        unsigned: value,
        signature: Signature {
            algorithm: "ed25519",
            key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })
    .map_err(|_| Error)?;
    // Shape/canonicality gate is the same production parser used by consume.
    runne_native_qualification::PendingQualificationRunBootstrapProof::from_signed_bytes(
        bytes.clone(),
    )
    .map_err(|_| Error)?;
    Ok(bytes)
}
