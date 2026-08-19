fn immediate_transaction(conn: &mut schema::ManagedConnection) -> Result<Transaction<'_>, IntentError> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| IntentError::CorruptStore)
}

fn find_intent<P: rusqlite::types::ToSql + ?Sized>(
    tx: &Transaction<'_>,
    column: &str,
    value: &P,
) -> Result<Option<ConsumptionIntent>, IntentError> {
    let sql = format!(
        "SELECT intent_id, idempotency_key, state, gate_head_snapshot_digest,
                target_artifact_digest, integrity_digest
         FROM consumption_intents WHERE {column} = ?1"
    );
    match tx.query_row(&sql, [value], read_intent_row) {
        Ok(intent) => Ok(Some(intent)),
        Err(SqliteError::QueryReturnedNoRows) => Ok(None),
        Err(_) => Err(IntentError::CorruptStore),
    }
}

fn reservation_digest(
    intent_id: &IntentID,
    key: &str,
    snapshot: &VerificationDigest,
    target: &VerificationDigest,
) -> VerificationDigest {
    canonical_reservation_digest(
        intent_id.as_bytes(),
        key,
        snapshot.as_bytes(),
        target.as_bytes(),
    )
}

pub(crate) fn canonical_reservation_digest(
    intent_id: &[u8; 16],
    key: &str,
    snapshot: &[u8; 32],
    target: &[u8; 32],
) -> VerificationDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"runne-runtime/consumption-intent-reservation/v1\0");
    hasher.update(intent_id);
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key.as_bytes());
    hasher.update(snapshot);
    hasher.update(target);
    VerificationDigest::from_bytes(hasher.finalize().into())
}

fn read_intent_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsumptionIntent> {
    let intent_id_blob: Vec<u8> = row.get(0)?;
    let snapshot_blob: Vec<u8> = row.get(3)?;
    let target_blob: Vec<u8> = row.get(4)?;
    let integrity_blob: Vec<u8> = row.get(5)?;
    let intent_id = exact_array::<16>(&intent_id_blob)?;
    let snapshot = exact_array::<32>(&snapshot_blob)?;
    let target = exact_array::<32>(&target_blob)?;
    let integrity = exact_array::<32>(&integrity_blob)?;
    let state = match row.get::<_, String>(2)?.as_str() {
        "Reserved" => IntentState::Reserved,
        "Dispatching" => IntentState::Dispatching,
        "Completed" => IntentState::Completed,
        "Failed" => IntentState::Failed,
        "Invalidated" => IntentState::Invalidated,
        "Abandoned" => IntentState::Abandoned,
        _ => return Err(malformed_row()),
    };
    let intent_id = uuid::Uuid::from_bytes(intent_id);
    let idempotency_key: String = row.get(1)?;
    let gate_head_snapshot_digest = VerificationDigest::from_bytes(snapshot);
    let target_artifact_digest = VerificationDigest::from_bytes(target);
    let integrity_digest = VerificationDigest::from_bytes(integrity);
    if integrity_digest
        != reservation_digest(
            &intent_id,
            &idempotency_key,
            &gate_head_snapshot_digest,
            &target_artifact_digest,
        )
    {
        return Err(malformed_row());
    }
    Ok(ConsumptionIntent {
        intent_id,
        idempotency_key,
        state,
        gate_head_snapshot_digest,
        target_artifact_digest,
        integrity_digest,
    })
}

fn exact_array<const N: usize>(value: &[u8]) -> rusqlite::Result<[u8; N]> {
    value.try_into().map_err(|_| malformed_row())
}

fn malformed_row() -> SqliteError {
    SqliteError::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed intent row",
        )),
    )
}

fn state_name(state: IntentState) -> &'static str {
    match state {
        IntentState::Reserved => "Reserved",
        IntentState::Dispatching => "Dispatching",
        IntentState::Completed => "Completed",
        IntentState::Failed => "Failed",
        IntentState::Invalidated => "Invalidated",
        IntentState::Abandoned => "Abandoned",
    }
}
