fn retention_gap_baseline_v2(
    tx: &rusqlite::Transaction<'_>,
    aggregate_type: i32,
    aggregate_id: &[u8; 16],
    lineage_id: &EventLogLineageId,
    server_secret: &[u8; 32],
    retention_manifest: &RetentionManifest,
) -> Result<ReplayRetentionBaselineCandidateV2, ReplayError> {
    let snapshot = crate::store::snapshot::load_unauthenticated_replay_projection(
        tx,
        i64::from(aggregate_type),
        aggregate_id,
    )
    .map_err(|_| {
        ReplayError::Integrity("V2 replay retention snapshot is unavailable".to_owned())
    })?;
    let floor = retention_manifest.retained_floor().ok_or_else(|| {
        ReplayError::Integrity("V2 replay retention floor is unavailable".to_owned())
    })?;
    let high_water = retention_manifest.high_water_position();
    if snapshot.aggregate_version != snapshot.event_sequence
        || snapshot.head_global_position < floor
        || snapshot.head_global_position > high_water
    {
        return Err(ReplayError::Integrity(
            "V2 replay retention snapshot binding is invalid".to_owned(),
        ));
    }
    ReplayRetentionBaselineCandidateV2::from_storage(ReplayRetentionBaselineCandidateV2Parts {
        promotion_projection_bytes: snapshot.promotion_projection_bytes,
        sequence: snapshot.event_sequence,
        version: snapshot.aggregate_version,
        baseline_global_position: snapshot.head_global_position,
        head_event_id: *snapshot.head_event_id.as_bytes(),
        head_integrity_digest: *snapshot.head_integrity_digest.as_bytes(),
        retained_floor: floor,
        captured_high_water: high_water,
        retention_generation: published_retention_generation(
            retention_manifest.retention_generation(),
        )?,
        retention_manifest_digest: baseline_resume_manifest_digest(
            lineage_id,
            RETENTION_GENERATION,
            floor,
            server_secret,
        ),
    })
    .map_err(|_| ReplayError::Integrity("V2 replay retention candidate is invalid".to_owned()))
}
