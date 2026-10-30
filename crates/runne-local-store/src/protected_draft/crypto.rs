use runne_secure_store::{MAX_MUTATION_PAYLOAD_ENVELOPE_OVERHEAD, SecurityProfileLock};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::types::{
    MAGIC, MAX_DRAFT_BYTES, MAX_DRAFT_PAYLOAD_BYTES, MAX_DRAFT_REVISION, ProtectedDraft,
    ProtectedDraftError, ProtectedDraftScope,
};

pub(super) fn validate_scope(scope: &ProtectedDraftScope) -> Result<(), ProtectedDraftError> {
    if !valid_id(&scope.project_id)
        || !valid_id(&scope.workspace_id)
        || [&scope.lineage, &scope.authority, &scope.principal]
            .iter()
            .any(|value| {
                value.is_empty()
                    || value.len() > 512
                    || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
            })
    {
        return Err(ProtectedDraftError::Invalid);
    }
    Ok(())
}

pub(super) fn scope_token(
    profile: [u8; 32],
    database: [u8; 32],
    scope: &ProtectedDraftScope,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"runne/local-store/protected-draft/scope-token/v1\0");
    digest.update(profile);
    digest.update(database);
    for field in scope_fields(scope) {
        digest.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(field.as_bytes());
    }
    let bytes = digest.finalize();
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(token, "{byte:02x}");
    }
    token
}

pub(super) fn validate_scope_token(value: &str) -> Result<(), ProtectedDraftError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtectedDraftError::ScopeMismatch);
    }
    Ok(())
}

pub(super) fn current_draft(
    connection: &Connection,
    lock: &SecurityProfileLock<'_>,
    profile: [u8; 32],
    database: [u8; 32],
    scope: &ProtectedDraftScope,
    token: &str,
) -> Result<ProtectedDraft, ProtectedDraftError> {
    let selector = params![
        scope.lineage,
        scope.authority,
        scope.principal,
        scope.project_id,
        scope.workspace_id
    ];
    let metadata = connection
        .query_row(
            "SELECT revision, deleted, length(payload) FROM protected_drafts WHERE lineage=?1 AND authority=?2 AND principal=?3 AND project_id=?4 AND workspace_id=?5",
            selector,
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?, row.get::<_, i64>(2)?)),
        )
        .optional()
        .map_err(|_| ProtectedDraftError::Storage)?;
    let Some((revision, deleted, length)) = metadata else {
        return Ok(ProtectedDraft {
            revision: 0,
            prompt: None,
            scope_token: token.to_owned(),
        });
    };
    if !(36..=MAX_DRAFT_PAYLOAD_BYTES).contains(&length) {
        return Err(ProtectedDraftError::Invalid);
    }
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM protected_drafts WHERE lineage=?1 AND authority=?2 AND principal=?3 AND project_id=?4 AND workspace_id=?5 AND revision=?6",
            params![scope.lineage, scope.authority, scope.principal, scope.project_id, scope.workspace_id, revision],
            |row| row.get(0),
        )
        .map_err(|_| ProtectedDraftError::Conflict)?;
    decode_draft(
        lock,
        profile,
        database,
        scope,
        token,
        Some((revision, deleted, Some(payload))),
    )
}

pub(super) fn decode_draft(
    lock: &SecurityProfileLock<'_>,
    profile: [u8; 32],
    database: [u8; 32],
    scope: &ProtectedDraftScope,
    token: &str,
    row: Option<(i64, bool, Option<Vec<u8>>)>,
) -> Result<ProtectedDraft, ProtectedDraftError> {
    let Some((revision, deleted, payload)) = row else {
        return Ok(ProtectedDraft {
            revision: 0,
            prompt: None,
            scope_token: token.to_owned(),
        });
    };
    let revision = u64::try_from(revision).map_err(|_| ProtectedDraftError::Invalid)?;
    if revision == 0 || revision > MAX_DRAFT_REVISION {
        return Err(ProtectedDraftError::Invalid);
    }
    let payload = payload.ok_or(ProtectedDraftError::Invalid)?;
    if payload.len() < MAGIC.len() + 28
        || payload.len() > MAX_DRAFT_BYTES + MAX_MUTATION_PAYLOAD_ENVELOPE_OVERHEAD
        || payload.get(..MAGIC.len()) != Some(MAGIC)
    {
        return Err(ProtectedDraftError::Invalid);
    }
    let plaintext = lock
        .decrypt_mutation_payload(
            database,
            &aad(profile, database, scope, revision),
            &payload[MAGIC.len()..],
        )
        .map_err(|_| ProtectedDraftError::Invalid)?;
    if deleted {
        if !plaintext.is_empty() {
            return Err(ProtectedDraftError::Invalid);
        }
        return Ok(ProtectedDraft {
            revision,
            prompt: None,
            scope_token: token.to_owned(),
        });
    }
    if plaintext.is_empty() || plaintext.len() > MAX_DRAFT_BYTES {
        return Err(ProtectedDraftError::Invalid);
    }
    let prompt = std::str::from_utf8(&plaintext)
        .map_err(|_| ProtectedDraftError::Invalid)?
        .to_owned();
    Ok(ProtectedDraft {
        revision,
        prompt: Some(prompt),
        scope_token: token.to_owned(),
    })
}

pub(super) fn seal(
    lock: &SecurityProfileLock<'_>,
    profile: [u8; 32],
    database: [u8; 32],
    scope: &ProtectedDraftScope,
    revision: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtectedDraftError> {
    let encrypted = lock
        .encrypt_mutation_payload(
            database,
            &aad(profile, database, scope, revision),
            plaintext,
        )
        .map_err(|_| ProtectedDraftError::Unavailable)?;
    let mut envelope = Vec::with_capacity(MAGIC.len() + encrypted.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&encrypted);
    Ok(envelope)
}

fn aad(
    profile: [u8; 32],
    database: [u8; 32],
    scope: &ProtectedDraftScope,
    revision: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(320);
    bytes.extend_from_slice(b"runne/local-store/protected-draft/aad/v2\0");
    bytes.extend_from_slice(&profile);
    bytes.extend_from_slice(&database);
    for field in scope_fields(scope) {
        bytes.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes.extend_from_slice(&revision.to_be_bytes());
    bytes
}

fn scope_fields(scope: &ProtectedDraftScope) -> [&str; 5] {
    [
        &scope.lineage,
        &scope.authority,
        &scope.principal,
        &scope.project_id,
        &scope.workspace_id,
    ]
}

fn valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8'..=b'9' | b'a'..=b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
}
