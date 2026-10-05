use super::*;

pub(super) fn decode_receipt(
    key: ToolInvocationKey,
    row: Stored,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    let semantic_digest = digest(row.1)?;
    let state = match row.0.as_str() {
        "proposed" => ToolInvocationState::Proposed,
        "approved" => ToolInvocationState::Approved,
        "denied" => ToolInvocationState::Denied,
        "claimed" => ToolInvocationState::Claimed,
        "uncertain" => ToolInvocationState::Uncertain,
        "result" => ToolInvocationState::Result,
        "cancelled" => ToolInvocationState::Cancelled,
        "audit_only" => ToolInvocationState::AuditOnly,
        _ => return Err(ToolInvocationStoreError::CorruptData),
    };
    let result = match (
        row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9, row.10, row.11, row.12,
    ) {
        (None, None, None, None, None, None, None, None, None, None, None) => None,
        (
            Some(result_hash),
            Some(length),
            Some(truncated),
            Some(receipt_hash),
            Some(ciphertext),
            Some(key_id),
            Some(key_version),
            Some(authority),
            Some(generation),
            Some(nonce),
            Some(plaintext_len),
        ) => {
            let key = runne_application::provider::ProviderJournalKeyBinding::new(
                fixed::<16>(key_id)?,
                u64::try_from(key_version).map_err(|_| ToolInvocationStoreError::CorruptData)?,
                fixed::<16>(authority)?,
                u64::try_from(generation).map_err(|_| ToolInvocationStoreError::CorruptData)?,
            )
            .map_err(|_| ToolInvocationStoreError::CorruptData)?;
            let payload = runne_application::provider::ProviderEncryptedPayload::new(
                fixed::<12>(nonce)?,
                ciphertext,
                u64::try_from(plaintext_len).map_err(|_| ToolInvocationStoreError::CorruptData)?,
                fixed::<32>(receipt_hash.clone())?,
            )
            .map_err(|_| ToolInvocationStoreError::CorruptData)?;
            if payload.plaintext_digest() != receipt_hash.as_slice() {
                return Err(ToolInvocationStoreError::CorruptData);
            }
            Some(ToolInvocationResult {
                bytes: Vec::new(),
                digest: digest(result_hash)?,
                actual_length: u64::try_from(length)
                    .map_err(|_| ToolInvocationStoreError::CorruptData)?,
                truncated: truncated != 0,
                receipt_payload: EncryptedToolPayloadV1 { key, payload },
            })
        }
        _ => return Err(ToolInvocationStoreError::CorruptData),
    };
    Ok(ToolInvocationReceipt {
        key,
        state,
        semantic_digest,
        result,
        budget: ToolInvocationBudget {
            effects_used: row.13 as u32,
            continuations_used: row.14 as u32,
        },
    })
}

pub(super) fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], ToolInvocationStoreError> {
    bytes
        .try_into()
        .map_err(|_| ToolInvocationStoreError::CorruptData)
}

// These fields jointly reconstruct and authenticate one encrypted payload.
#[allow(clippy::too_many_arguments)]
pub(super) fn load_payload(
    connection: &rusqlite::Connection,
    key_id: Vec<u8>,
    key_version: i64,
    authority: Vec<u8>,
    generation: i64,
    nonce: Vec<u8>,
    ciphertext_column: &str,
    length_column: &str,
    digest_column: &str,
    key: ToolInvocationKey,
) -> Result<EncryptedToolPayloadV1, ToolInvocationStoreError> {
    let sql = format!(
        "SELECT {ciphertext_column},{length_column},{digest_column} FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4"
    );
    let (ciphertext, length, digest_bytes): (Vec<u8>, i64, Vec<u8>) = connection
        .query_row(
            &sql,
            params![
                key.taskrun_id.as_bytes(),
                key.attempt_id.as_bytes(),
                key.cycle_id.as_bytes(),
                i64::from(key.proposal_index)
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let binding = runne_application::provider::ProviderJournalKeyBinding::new(
        fixed::<16>(key_id)?,
        u64::try_from(key_version).map_err(|_| ToolInvocationStoreError::CorruptData)?,
        fixed::<16>(authority)?,
        u64::try_from(generation).map_err(|_| ToolInvocationStoreError::CorruptData)?,
    )
    .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let payload = runne_application::provider::ProviderEncryptedPayload::new(
        fixed::<12>(nonce)?,
        ciphertext,
        u64::try_from(length).map_err(|_| ToolInvocationStoreError::CorruptData)?,
        fixed::<32>(digest_bytes)?,
    )
    .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    Ok(EncryptedToolPayloadV1 {
        key: binding,
        payload,
    })
}

pub(super) fn digest(bytes: Vec<u8>) -> Result<IntegrityDigest, ToolInvocationStoreError> {
    Ok(IntegrityDigest::from_bytes(
        bytes
            .try_into()
            .map_err(|_| ToolInvocationStoreError::CorruptData)?,
    ))
}
