fn retained_inventory(conn: &Connection) -> Result<RetainedInventory, ReplayError> {
    let mut statement = conn
        .prepare(
            "SELECT event_id, aggregate_type, aggregate_id, sequence,
                    global_position, timestamp, sensitivity, schema_version,
                    causation_id, command_id, idempotency_key, actor,
                    payload, integrity_digest, correlation_id,
                    correlation_type, integrity_profile
             FROM events
             ORDER BY global_position",
        )
        .map_err(|error| ReplayError::Storage(format!("prepare retention inventory: {error}")))?;
    let events = statement
        .query_map([], read_replay_event)
        .map_err(|error| ReplayError::Storage(format!("read retention inventory: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| replay_row_error("decode retention inventory", error))?;
    let mut gap = None;
    for pair in events.windows(2) {
        let expected = pair[0].global_position.checked_add(1).ok_or_else(|| {
            ReplayError::Integrity("retained global position overflow".to_owned())
        })?;
        if pair[1].global_position != expected {
            gap = Some((expected, pair[1].global_position.saturating_sub(1)));
            break;
        }
    }
    Ok(RetainedInventory {
        events,
        interior_gap: gap,
    })
}

fn retention_manifest_for_events(
    events: &[ReplayEvent],
    lineage_id: EventLogLineageId,
    server_secret: &[u8; 32],
) -> Result<RetentionManifest, ReplayError> {
    let retained_floor = events.first().map(|event| event.global_position);
    let high_water_position = events.last().map_or(0, |event| event.global_position);
    let maximum_encoded_event_bytes = events
        .iter()
        .map(|event| {
            validate_replay_event_integrity(event)
                .map(|(_, encoded_size)| encoded_size)
                .map_err(|error| replay_row_error("measure retained replay event", error))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    let mut message = b"gocode/replay-retention-manifest/v1\0".to_vec();
    message.extend_from_slice(lineage_id.as_bytes());
    message.extend_from_slice(&RETENTION_GENERATION.to_be_bytes());
    match retained_floor {
        Some(floor) => {
            message.push(1);
            message.extend_from_slice(&floor.to_be_bytes());
        }
        None => {
            message.push(0);
            message.extend_from_slice(&0_i64.to_be_bytes());
        }
    }
    message.extend_from_slice(&high_water_position.to_be_bytes());
    message.extend_from_slice(
        &u64::try_from(maximum_encoded_event_bytes)
            .map_err(|_| ReplayError::Integrity("retained event size overflow".to_owned()))?
            .to_be_bytes(),
    );
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("fixed HMAC key size");
    mac.update(&message);
    let evidence: [u8; 32] = mac.finalize().into_bytes().into();
    RetentionManifest::new(
        lineage_id,
        RETENTION_GENERATION,
        retained_floor,
        high_water_position,
        maximum_encoded_event_bytes,
        IntegrityDigest::from_bytes(evidence),
    )
    .map_err(|_| ReplayError::Integrity("invalid retention manifest".to_owned()))
}

fn build_gap_range_ref(
    lineage_id: &EventLogLineageId,
    retention_generation: u64,
    missing_start: i64,
    missing_end: i64,
    scope: &ReplayScope,
    authorization_epoch: i64,
    server_secret: &[u8; 32],
) -> GapRangeRef {
    let mut message = b"gocode/replay-gap-range/v1\0".to_vec();
    message.extend_from_slice(lineage_id.as_bytes());
    message.extend_from_slice(&retention_generation.to_be_bytes());
    message.extend_from_slice(&missing_start.to_be_bytes());
    message.extend_from_slice(&missing_end.to_be_bytes());
    message.extend_from_slice(&scope.canonical_digest());
    message.extend_from_slice(&authorization_epoch.to_be_bytes());
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("fixed HMAC key size");
    mac.update(&message);
    let integrity: [u8; 32] = mac.finalize().into_bytes().into();
    GapRangeRef::new(IntegrityDigest::from_bytes(integrity))
        .expect("HMAC output is a non-empty gap reference")
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn invalid_column(index: usize, data_type: rusqlite::types::Type) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        data_type,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid canonical replay event column",
        )),
    )
}

fn replay_row_error(context: &'static str, error: rusqlite::Error) -> ReplayError {
    if matches!(
        error,
        rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
            | rusqlite::Error::InvalidColumnType(..)
    ) {
        ReplayError::Integrity("stored replay event failed integrity validation".to_owned())
    } else {
        ReplayError::Storage(format!("{context}: {error}"))
    }
}

fn fixed_blob<const N: usize>(blob: Vec<u8>, index: usize) -> rusqlite::Result<[u8; N]> {
    blob.try_into()
        .map_err(|_| invalid_column(index, rusqlite::types::Type::Blob))
}

fn optional_event_id(blob: Option<Vec<u8>>, index: usize) -> rusqlite::Result<Option<[u8; 16]>> {
    blob.map(|value| fixed_blob(value, index)).transpose()
}
