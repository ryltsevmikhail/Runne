impl ProviderDispatchRepository for SqliteProviderDispatchStore {
    fn persist_prepared(
        &self,
        record: &ContractPreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::persist_prepared(
            self,
            &PreparedProviderRecord {
                call_id: record.call_id,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn claim(
        &self,
        claim: &ContractProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError> {
        SqliteProviderDispatchStore::claim(
            self,
            &ProviderDispatchClaim {
                call_id: claim.call_id,
                attempt_id: claim.attempt_id,
                permit_id: claim.permit_id,
                prepared_digest: claim.prepared_digest,
                render_digest: claim.render_digest,
                profile_digest: claim.profile_digest,
                token_reservation_id: claim.token_reservation_id,
                cost_reservation_id: claim.cost_reservation_id,
                fencing_token: claim.fencing_token,
                provider_idempotency_key: claim.provider_idempotency_key.clone(),
            },
        )
        .map(|outcome| match outcome {
            ProviderClaimOutcome::Winner { permit_id } => {
                ProviderRepositoryClaimOutcome::Winner { permit_id }
            }
            ProviderClaimOutcome::Existing { attempt_id, state } => {
                ProviderRepositoryClaimOutcome::Existing {
                    attempt_id,
                    state: repository_state(state),
                }
            }
        })
        .map_err(repository_error)
    }

    fn mark_streaming(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        stream_id: ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_streaming(
            self,
            &MarkProviderStreaming {
                attempt_id,
                fencing_token,
                stream_id,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn mark_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_uncertain(self, attempt_id, fencing_token)
            .map(|_| ())
            .map_err(repository_error)
    }
}
