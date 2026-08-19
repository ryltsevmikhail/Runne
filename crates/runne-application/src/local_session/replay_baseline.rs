impl AuthenticatedReplayBaselineIssuer {
    /// Signs one structural baseline while this exact authenticated session remains live.
    pub(crate) fn issue(
        &self,
        scope: runne_domain::replay::ReplayScope,
        candidate: crate::replay_service::ReplayRetentionBaselineCandidateV1,
        now_monotonic: std::time::Duration,
        issued_at_unix_ms: u64,
        requested_expires_at_unix_ms: u64,
    ) -> Result<runne_api::ReplayRetentionBaselineWireV1, LocalSessionError> {
        if self.state.revoked.load(Ordering::Acquire) || now_monotonic >= self.expires_at_monotonic
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let max_ttl = self
            .expires_at_monotonic
            .saturating_sub(now_monotonic)
            .as_millis()
            .min(30_000);
        let expires = requested_expires_at_unix_ms
            .min(issued_at_unix_ms.saturating_add(u64::try_from(max_ttl).unwrap_or(0)));
        if expires <= issued_at_unix_ms {
            return Err(LocalSessionError::Unauthorized);
        }
        let (scope_kind, scope_id) = replay_baseline_scope(&scope)?;
        if candidate.projection.aggregate_kind() != scope_kind
            || candidate.projection.aggregate_id() != scope_id
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let stable = self.binding.stable();
        let fields = runne_api::UnauthenticatedReplayRetentionBaselineFieldsV1 {
            schema_version: 1,
            authority_id: *stable.authority_id(),
            principal_id: stable.principal_id().as_str().to_owned(),
            lineage_id: *stable.lineage_id().as_bytes(),
            runtime_session_binding_digest: self.binding.canonical_digest(),
            replay_scope_digest: scope.canonical_digest(),
            aggregate_kind: candidate.projection.aggregate_kind(),
            aggregate_id: candidate.projection.aggregate_id(),
            sequence: candidate.sequence,
            version: candidate.version,
            baseline_global_position: candidate.baseline_global_position,
            projection_codec: 1,
            projection_bytes: candidate.projection.encoded_bytes().to_vec(),
            projection_digest: *candidate.projection.projection_digest(),
            retained_floor: candidate.retained_floor,
            captured_high_water: candidate.captured_high_water,
            retention_generation: candidate.retention_generation,
            retention_witness: candidate.retention_witness,
            issued_at_unix_ms,
            expires_at_unix_ms: expires,
            witness_mac: [0; 32],
        };
        let unsigned =
            runne_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(fields);
        runne_api::validate_unauthenticated_replay_retention_baseline(
            &unsigned,
            scope_kind,
            &scope_id,
        )
        .map_err(|_| LocalSessionError::Unauthorized)?;
        let mut fields = unsigned.to_unauthenticated_fields();
        fields.witness_mac = self
            .authority
            .replay_baseline_mac(fields.runtime_session_binding_digest, &unsigned);
        Ok(runne_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(fields))
    }
}

fn replay_baseline_scope(
    scope: &runne_domain::replay::ReplayScope,
) -> Result<(runne_api::ApiReplayAggregateKind, [u8; 16]), LocalSessionError> {
    match scope {
        runne_domain::replay::ReplayScope::Aggregate {
            aggregate_type: 1,
            aggregate_id,
        } => Ok((runne_api::ApiReplayAggregateKind::TaskRun, *aggregate_id)),
        runne_domain::replay::ReplayScope::Aggregate {
            aggregate_type: 2,
            aggregate_id,
        } => Ok((runne_api::ApiReplayAggregateKind::Conversation, *aggregate_id)),
        _ => Err(LocalSessionError::Unauthorized),
    }
}

impl RuntimeSessionAuthority {
    fn replay_baseline_mac(
        &self,
        binding_digest: [u8; 32],
        wire: &runne_api::ReplayRetentionBaselineWireV1,
    ) -> [u8; 32] {
        let mut derive = HmacSha256::new_from_slice(self.0.as_ref()).expect("fixed HMAC key");
        derive.update(runne_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V1);
        derive.update(&binding_digest);
        let key: [u8; 32] = derive.finalize().into_bytes().into();
        let mut mac = HmacSha256::new_from_slice(&key).expect("fixed HMAC key");
        mac.update(&runne_api::replay_retention_baseline_transcript(wire));
        mac.finalize().into_bytes().into()
    }
}
