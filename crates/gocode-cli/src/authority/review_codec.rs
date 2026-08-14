use super::{
    AuthorityReviewV1, ReviewBackup, ReviewDocument, ReviewError, ReviewOutput, ReviewRotation,
    ReviewSubject,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn canonical_json(review: &AuthorityReviewV1) -> Result<Vec<u8>, ReviewError> {
    let mut docs = review.documents.iter().collect::<Vec<_>>();
    docs.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let root = BTreeMap::from([
        ("backup", option_value(review.backup.as_ref(), backup_value)),
        ("continuity", string(&review.continuity)),
        (
            "documents",
            Value::Array(docs.into_iter().map(document_value).collect()),
        ),
        ("issued_at", option_string(review.issued_at.as_ref())),
        ("key_epoch", Value::Number(review.key_epoch.into())),
        ("key_fingerprint", string(&review.key_fingerprint)),
        ("key_id", string(&review.key_id)),
        ("operation", string(&review.operation)),
        ("output", option_value(review.output.as_ref(), output_value)),
        ("profile", option_string(review.profile.as_ref())),
        ("purpose", option_string(review.purpose.as_ref())),
        ("repository_id", string(&review.repository_id)),
        (
            "rotation",
            option_value(review.rotation.as_ref(), rotation_value),
        ),
        ("schema_version", string(&review.schema_version)),
        (
            "signing_transcript_sha256",
            option_string(review.signing_transcript_sha256.as_ref()),
        ),
        (
            "subject",
            option_value(review.subject.as_ref(), subject_value),
        ),
        ("trust_config_sha256", string(&review.trust_config_sha256)),
    ]);
    let mut bytes = serde_json::to_vec(&root).map_err(|_| ReviewError)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn document_value(x: &ReviewDocument) -> Value {
    object([
        ("blob_oid", string(&x.blob_oid)),
        ("byte_length", Value::Number(x.byte_length.into())),
        ("content_sha256", string(&x.content_sha256)),
        ("mode", string(&x.mode)),
        ("path", string(&x.path)),
        ("schema_id", option_string(x.schema_id.as_ref())),
    ])
}
fn subject_value(x: &ReviewSubject) -> Value {
    object([
        ("commit_oid", string(&x.commit_oid)),
        ("object_format", string(&x.object_format)),
        ("tree_oid", string(&x.tree_oid)),
    ])
}
fn output_value(x: &ReviewOutput) -> Value {
    object([
        ("artifact_sha256", option_string(x.artifact_sha256.as_ref())),
        (
            "byte_length",
            x.byte_length
                .map_or(Value::Null, |v| Value::Number(v.into())),
        ),
        ("kind", string(&x.kind)),
        ("locator", string(&x.locator)),
    ])
}
fn rotation_value(x: &ReviewRotation) -> Value {
    object([
        ("new_epoch", Value::Number(x.new_epoch.into())),
        ("new_key_fingerprint", string(&x.new_key_fingerprint)),
        ("new_key_id", string(&x.new_key_id)),
        ("new_public_key", string(&x.new_public_key)),
        (
            "old_authorization_payload_sha256",
            string(&x.old_authorization_payload_sha256),
        ),
        ("old_epoch", Value::Number(x.old_epoch.into())),
        ("old_key_id", string(&x.old_key_id)),
        (
            "predecessor_config_sha256",
            string(&x.predecessor_config_sha256),
        ),
    ])
}
fn backup_value(x: &ReviewBackup) -> Value {
    object([
        ("backup_bytes_sha256", string(&x.backup_bytes_sha256)),
        ("iterations", Value::Number(x.iterations.into())),
        ("kdf_algorithm", string(&x.kdf_algorithm)),
        ("memory_kib", Value::Number(x.memory_kib.into())),
        ("parallelism", Value::Number(x.parallelism.into())),
    ])
}
fn object<const N: usize>(x: [(&str, Value); N]) -> Value {
    Value::Object(
        BTreeMap::from(x)
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
    )
}
fn option_value<T>(x: Option<&T>, f: fn(&T) -> Value) -> Value {
    x.map_or(Value::Null, f)
}
fn option_string(x: Option<&String>) -> Value {
    x.map_or(Value::Null, |x| string(x))
}
fn string(x: &str) -> Value {
    Value::String(x.into())
}
