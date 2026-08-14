impl ReplayBaselineSeed {
    /// Derives persistence-only evidence from a verified common V2 capability.
    ///
    /// This adapter never receives a wire, MAC key, raw witness, or snapshot;
    /// the common capability has already authenticated those before it reaches
    /// the local-store trust boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the authenticated evidence cannot fit the sealed
    /// local V8 baseline representation.
    pub fn from_authenticated_v2(
        scope: &ReplayScopeKey,
        baseline: &gocode_api::AuthenticatedReplayBaselineV2,
    ) -> Result<Self, ReplayStoreError> {
        let payload = baseline
            .local_projection()
            .map_err(|_| ReplayStoreError::InvalidBaseline)?
            .local_persistence_bytes()
            .to_vec();
        if baseline.promotion_codec() != 1
            || payload.is_empty()
            || payload.len() > 1_048_576
            || baseline.replay_scope_digest()
                != &gocode_api::canonical_aggregate_replay_scope_digest(
                    baseline.aggregate_kind(),
                    baseline.aggregate_id(),
                )
        {
            return Err(ReplayStoreError::InvalidBaseline);
        }
        let expected_scope = match baseline.aggregate_kind() {
            gocode_api::ApiReplayAggregateKind::Conversation => {
                format!("conversation:{}", uuid_string(baseline.aggregate_id()))
            }
            gocode_api::ApiReplayAggregateKind::TaskRun => {
                format!("task_run:{}", uuid_string(baseline.aggregate_id()))
            }
        };
        if scope.runtime_authority != hex_bytes(baseline.authority_id())
            || scope.principal != baseline.principal_id()
            || scope.lineage != uuid_string(baseline.lineage_id())
            || scope.scope != expected_scope
            || scope.binding_digest != hex_bytes(&baseline.durable_replay_binding_digest())
        {
            return Err(ReplayStoreError::InvalidBaseline);
        }
        let numbers = [
            baseline.sequence(),
            u64::try_from(baseline.baseline_global_position())
                .map_err(|_| ReplayStoreError::InvalidBaseline)?,
            u64::try_from(baseline.retained_floor()).map_err(|_| ReplayStoreError::InvalidBaseline)?,
            u64::try_from(baseline.captured_high_water())
                .map_err(|_| ReplayStoreError::InvalidBaseline)?,
            baseline.retention_generation(),
            baseline.issued_at_unix_ms(),
            baseline.expires_at_unix_ms(),
        ];
        if numbers.into_iter().any(|value| value == 0) {
            return Err(ReplayStoreError::InvalidBaseline);
        }
        Ok(Self {
            session_binding: hex_bytes(baseline.runtime_session_binding_digest()),
            promotion_codec: "gocode-replay-promotion-v1".to_owned(),
            payload,
            scope_digest: scope_digest(scope),
            authenticated_scope_digest: hex_bytes(baseline.replay_scope_digest()),
            schema_version: 2,
            head_event_id: uuid_string(baseline.head_event_id()),
            head_integrity_digest: hex_bytes(baseline.head_integrity_digest()),
            retention_manifest_digest: hex_bytes(baseline.retention_manifest_digest()),
            witness_digest: hex_bytes(&baseline.local_evidence_digest()),
            retention_floor: numbers[2], retention_high_water: numbers[3],
            retention_generation: numbers[4], issued_at: numbers[5],
            baseline_sequence: numbers[0], baseline_version: numbers[0],
            baseline_position: numbers[1], expires_at: numbers[6],
        })
    }
}

fn hex_bytes(value: &[u8]) -> String {
    use std::fmt::Write as _;
    value.iter().fold(String::with_capacity(value.len() * 2), |mut out, byte| {
        write!(&mut out, "{byte:02x}").expect("writing to String is infallible");
        out
    })
}

fn uuid_string(value: &[u8; 16]) -> String {
    let hex = hex_bytes(value);
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}
