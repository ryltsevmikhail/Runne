#[allow(clippy::too_many_arguments)]
fn retention_gap_baseline(
    tx: &rusqlite::Transaction<'_>,
    aggregate_type: i32,
    aggregate_id: &[u8; 16],
    authorization_epoch: i64,
    lineage_id: &EventLogLineageId,
    server_secret: &[u8; 32],
    retention_manifest: &RetentionManifest,
    missing_start: i64,
    missing_end: i64,
) -> Result<ReplayRetentionBaselineCandidateV1, ReplayError> {
    let snapshot = crate::store::snapshot::load_unauthenticated_replay_projection(
        tx,
        i64::from(aggregate_type),
        aggregate_id,
    )
    .map_err(|_| {
        ReplayError::Integrity("replay retention snapshot is unavailable".to_owned())
    })?;
    let retained_floor = retention_manifest.retained_floor().ok_or_else(|| {
        ReplayError::Integrity("replay retention floor is unavailable".to_owned())
    })?;
    if snapshot.head_global_position > retention_manifest.high_water_position()
        || snapshot.aggregate_version != snapshot.event_sequence
    {
        return Err(ReplayError::Integrity(
            "replay retention snapshot binding is invalid".to_owned(),
        ));
    }
    let aggregate_type = u8::try_from(aggregate_type)
        .map_err(|_| ReplayError::Integrity("invalid replay aggregate type".to_owned()))?;
    let retention_witness = build_gap_range_ref(
        lineage_id,
        retention_manifest.retention_generation(),
        missing_start,
        missing_end,
        &ReplayScope::Aggregate {
            aggregate_type,
            aggregate_id: *aggregate_id,
        },
        authorization_epoch,
        server_secret,
    );
    Ok(ReplayRetentionBaselineCandidateV1 {
        projection: snapshot.projection,
        sequence: snapshot.event_sequence,
        version: snapshot.aggregate_version,
        baseline_global_position: snapshot.head_global_position,
        retained_floor,
        captured_high_water: retention_manifest.high_water_position(),
        retention_generation: published_retention_generation(
            retention_manifest.retention_generation(),
        )?,
        retention_witness: *retention_witness.integrity().as_bytes(),
    })
}
