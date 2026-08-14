//! Raw canonical Ed25519 settlement/readback for the publication effect.
#![allow(clippy::missing_errors_doc, dead_code)] // Fixture-only executor-signed evidence.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::Digest;
use crate::publication_effect_types::PublicationEffectError;

const SCHEMA: &str = "gocode.release.publication-effect-settlement/1";

/// Executor-signed publication-effect settlement payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationSettlement {
    pub schema_version: String,
    pub idempotency_namespace: String,
    pub generation: u64,
    pub destination_readback_sha256: String,
    pub executable_sha256: String,
    pub workflow_sha256: String,
    pub observed_result: String,
}

/// Raw signed settlement: canonical bytes plus a detached executor signature.
pub struct RawPublicationSettlement {
    pub raw: Vec<u8>,
    pub signature: [u8; 64],
}

impl RawPublicationSettlement {
    /// Sign a canonical settlement for a fixture executor key.
    pub fn signed(settlement: &PublicationSettlement, key: &SigningKey) -> Self {
        let mut raw = serde_json::to_vec(&crate::wire::sorted_value(
            serde_json::to_value(settlement).expect("settlement serializes"),
        ))
        .expect("sorted settlement serializes");
        raw.push(b'\n');
        let signature = key.sign(&raw).to_bytes();
        Self { raw, signature }
    }

    /// Verify canonical bytes and the executor signature, returning the bound digest.
    pub fn verified(
        self,
        public_key: &[u8; 32],
    ) -> Result<(PublicationSettlement, Digest), PublicationEffectError> {
        let value: serde_json::Value = crate::wire::strict_json::parse(&self.raw)
            .map_err(|_| PublicationEffectError::SettlementMismatch)?;
        let settlement: PublicationSettlement = serde_json::from_value(value)
            .map_err(|_| PublicationEffectError::SettlementMismatch)?;
        if !settlement.is_valid() {
            return Err(PublicationEffectError::SettlementMismatch);
        }
        let mut canonical = serde_json::to_vec(&crate::wire::sorted_value(
            serde_json::to_value(&settlement)
                .map_err(|_| PublicationEffectError::SettlementMismatch)?,
        ))
        .map_err(|_| PublicationEffectError::SettlementMismatch)?;
        canonical.push(b'\n');
        if canonical != self.raw {
            return Err(PublicationEffectError::SettlementMismatch);
        }
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| PublicationEffectError::SettlementMismatch)?;
        key.verify_strict(&self.raw, &Signature::from_bytes(&self.signature))
            .map_err(|_| PublicationEffectError::SettlementMismatch)?;
        let digest = Digest::from_bytes(Sha256::digest(&self.raw[..self.raw.len() - 1]).into());
        Ok((settlement, digest))
    }
}

impl PublicationSettlement {
    fn is_valid(&self) -> bool {
        self.schema_version == SCHEMA
            && self.generation > 0
            && !self.idempotency_namespace.is_empty()
            && !self.idempotency_namespace.chars().any(char::is_whitespace)
            && [
                &self.destination_readback_sha256,
                &self.executable_sha256,
                &self.workflow_sha256,
            ]
            .into_iter()
            .all(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            && matches!(
                self.observed_result.as_str(),
                "succeeded" | "absent" | "inconclusive"
            )
    }
}
