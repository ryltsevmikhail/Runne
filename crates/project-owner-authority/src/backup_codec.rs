//! Strict canonical JSON codec for public encrypted-backup metadata.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    AuthorityError, BackupMetadataV1, BackupParameters, backup::BACKUP_SCHEMA, trust_canonical::hex,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: String,
    repository_id: String,
    key_id: String,
    key_epoch: u64,
    key_fingerprint: String,
    kdf: Kdf,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

pub fn parse(bytes: &[u8]) -> Result<BackupMetadataV1, AuthorityError> {
    if bytes.len() > 2_048 {
        return Err(AuthorityError::InvalidBackupMetadata);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| AuthorityError::InvalidUtf8)?;
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let wire =
        Wire::deserialize(&mut deserializer).map_err(|_| AuthorityError::InvalidBackupMetadata)?;
    if deserializer.end().is_err()
        || !source.ends_with('\n')
        || source[..source.len() - 1].contains(char::is_whitespace)
    {
        return Err(AuthorityError::InvalidBackupMetadata);
    }
    if !(22..=86).contains(&wire.salt.len())
        || wire.nonce.len() != 32
        || wire.ciphertext.len() != 64
    {
        return Err(AuthorityError::InvalidBackupMetadata);
    }
    let metadata = BackupMetadataV1 {
        repository_id: wire.repository_id,
        key_id: decode_hex(&wire.key_id)?,
        key_epoch: wire.key_epoch,
        key_fingerprint: decode_hex(&wire.key_fingerprint)?,
        parameters: BackupParameters::new(
            wire.kdf.memory_kib,
            wire.kdf.iterations,
            wire.kdf.parallelism,
        )?,
        salt: decode_binary(&wire.salt)?,
        nonce: decode_fixed(&wire.nonce)?,
        ciphertext: decode_binary(&wire.ciphertext)?,
    };
    crate::backup_validation::validate_metadata(&metadata)?;
    if wire.schema_version != BACKUP_SCHEMA
        || wire.kdf.algorithm != "Argon2id"
        || canonical(&metadata, true)? != bytes
    {
        return Err(AuthorityError::InvalidBackupMetadata);
    }
    Ok(metadata)
}

pub fn canonical(metadata: &BackupMetadataV1, ciphertext: bool) -> Result<Vec<u8>, AuthorityError> {
    let kdf = object_array([
        ("algorithm", Value::String("Argon2id".into())),
        (
            "iterations",
            Value::Number(metadata.parameters.iterations.into()),
        ),
        (
            "memory_kib",
            Value::Number(metadata.parameters.memory_kib.into()),
        ),
        (
            "parallelism",
            Value::Number(metadata.parameters.parallelism.into()),
        ),
    ]);
    let mut values = vec![
        ("kdf", kdf),
        ("key_epoch", Value::Number(metadata.key_epoch.into())),
        (
            "key_fingerprint",
            Value::String(hex(&metadata.key_fingerprint)),
        ),
        ("key_id", Value::String(hex(&metadata.key_id))),
        (
            "nonce",
            Value::String(URL_SAFE_NO_PAD.encode(metadata.nonce)),
        ),
        (
            "repository_id",
            Value::String(metadata.repository_id.clone()),
        ),
        (
            "salt",
            Value::String(URL_SAFE_NO_PAD.encode(&metadata.salt)),
        ),
        ("schema_version", Value::String(BACKUP_SCHEMA.into())),
    ];
    if ciphertext {
        values.push((
            "ciphertext",
            Value::String(URL_SAFE_NO_PAD.encode(&metadata.ciphertext)),
        ));
    }
    values.sort_by_key(|(key, _)| *key);
    let mut bytes =
        serde_json::to_vec(&object_pairs(values)).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn object_array<const N: usize>(values: [(&str, Value); N]) -> Value {
    object_pairs(values)
}

fn object_pairs<'a>(values: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    Value::Object(
        values
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

fn decode_binary(value: &str) -> Result<Vec<u8>, AuthorityError> {
    if value.is_empty()
        || value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AuthorityError::InvalidBackupMetadata);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthorityError::InvalidBackupMetadata)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], AuthorityError> {
    decode_binary(value)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidBackupMetadata)
}

fn decode_hex(value: &str) -> Result<[u8; 32], AuthorityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AuthorityError::InvalidBackupMetadata);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Ok(bytes)
}

const fn hex_digit(value: u8) -> Result<u8, AuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityError::InvalidBackupMetadata),
    }
}
