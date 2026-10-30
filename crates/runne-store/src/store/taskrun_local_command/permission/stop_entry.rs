use super::*;

impl crate::store::StoreTransaction {
    /// Persists the first stop reason for a captured V68 command.
    pub fn record_local_command_permission_stop(
        &self,
        identity: &runne_application::ports::TaskRunAssignmentIdentity,
        binding: &runne_application::permission_modes::LocalCommandPermissionBindingV1,
        reason: u8,
    ) -> Result<u8, runne_application::ports::EventStoreError> {
        use runne_application::ports::EventStoreError;
        if identity != binding.assignment() || !(1..=6).contains(&reason) {
            return Err(EventStoreError::CorruptData);
        }
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        let (digest, _) = stop::read_binding(&tx, identity, binding)?;
        let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
            &tx,
            identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if !matches!(
            stream.state,
            runne_domain::task_run::TaskRunState::Running
                | runne_domain::task_run::TaskRunState::Cancelling
        ) {
            return Err(EventStoreError::CorruptData);
        }
        let (version, event_id) = stop::stop_anchor(&stream, reason)?;
        stop::record_stop(
            &tx,
            identity.taskrun_id.as_bytes(),
            identity.attempt_id.as_bytes(),
            &digest,
            reason,
            version,
            &event_id,
            model::now_ms(),
        )?;
        let saved = stop::read_stop(
            &tx,
            identity.taskrun_id.as_bytes(),
            identity.attempt_id.as_bytes(),
            &digest,
        )?
        .ok_or(EventStoreError::CorruptData)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)?;
        Ok(saved)
    }

    /// Reads the first persisted stop reason for this exact captured binding.
    pub fn local_command_permission_stop_reason(
        &self,
        identity: &runne_application::ports::TaskRunAssignmentIdentity,
        binding: &runne_application::permission_modes::LocalCommandPermissionBindingV1,
    ) -> Result<Option<u8>, runne_application::ports::EventStoreError> {
        use runne_application::ports::EventStoreError;
        if identity != binding.assignment() {
            return Err(EventStoreError::CorruptData);
        }
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let (digest, _) = stop::read_binding(&reader, identity, binding)?;
        stop::read_stop(
            &reader,
            identity.taskrun_id.as_bytes(),
            identity.attempt_id.as_bytes(),
            &digest,
        )
    }
}
