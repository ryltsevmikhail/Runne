use runne_project_owner_authority::framed_transcript;
use sha2::{Digest as _, Sha256};

#[path = "review_codec.rs"]
mod review_codec;
#[path = "review_validation.rs"]
mod review_validation;

const SCHEMA: &str = "gocode.authority.cli-review/1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorityReviewV1 {
    pub(super) schema_version: String,
    pub(super) operation: String,
    pub(super) repository_id: String,
    pub(super) purpose: Option<String>,
    pub(super) profile: Option<String>,
    pub(super) subject: Option<ReviewSubject>,
    pub(super) documents: Vec<ReviewDocument>,
    pub(super) trust_config_sha256: String,
    pub(super) key_id: String,
    pub(super) key_fingerprint: String,
    pub(super) key_epoch: u64,
    pub(super) issued_at: Option<String>,
    pub(super) signing_transcript_sha256: Option<String>,
    pub(super) output: Option<ReviewOutput>,
    pub(super) rotation: Option<ReviewRotation>,
    pub(super) backup: Option<ReviewBackup>,
    pub(super) continuity: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReviewSubject {
    pub(super) commit_oid: String,
    pub(super) object_format: String,
    pub(super) tree_oid: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReviewDocument {
    pub(super) blob_oid: String,
    pub(super) byte_length: u64,
    pub(super) content_sha256: String,
    pub(super) mode: String,
    pub(super) path: String,
    pub(super) schema_id: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReviewOutput {
    pub(super) artifact_sha256: Option<String>,
    pub(super) byte_length: Option<u64>,
    pub(super) kind: String,
    pub(super) locator: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReviewRotation {
    pub(super) new_epoch: u64,
    pub(super) new_key_fingerprint: String,
    pub(super) new_key_id: String,
    pub(super) new_public_key: String,
    pub(super) old_authorization_payload_sha256: String,
    pub(super) old_epoch: u64,
    pub(super) old_key_id: String,
    pub(super) predecessor_config_sha256: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReviewBackup {
    pub(super) kdf_algorithm: String,
    pub(super) iterations: u32,
    pub(super) memory_kib: u32,
    pub(super) parallelism: u32,
    pub(super) backup_bytes_sha256: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReviewError;

impl AuthorityReviewV1 {
    pub(super) fn canonical_json(&self) -> Result<Vec<u8>, ReviewError> {
        review_validation::validate(self)?;
        review_codec::canonical_json(self)
    }
    pub(super) fn review_sha256(&self) -> Result<String, ReviewError> {
        let bytes = self.canonical_json()?;
        let transcript = framed_transcript(SCHEMA.as_bytes(), &bytes).map_err(|_| ReviewError)?;
        Ok(hex(&Sha256::digest(transcript)))
    }
    pub(super) fn confirmation_challenge(&self) -> Result<String, ReviewError> {
        let digest = self.review_sha256()?;
        let suffix = &digest[digest.len() - 12..];
        Ok(if self.operation == "trust-reset" {
            format!("COMPROMISE-{suffix}")
        } else {
            suffix.into()
        })
    }
    pub(super) fn public_display(&self) -> Result<String, ReviewError> {
        let canonical = String::from_utf8(self.canonical_json()?).map_err(|_| ReviewError)?;
        Ok(format!(
            "{canonical}review_sha256={}\n",
            self.review_sha256()?
        ))
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(value, "{byte:02x}").expect("writing to String is infallible");
    }
    value
}

#[cfg(test)]
#[path = "review_tests.rs"]
mod review_tests;
