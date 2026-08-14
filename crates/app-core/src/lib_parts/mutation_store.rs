impl AppCore {
    /// Persists a normalized mutation before it can reach the runtime.
    ///
    /// Legacy unanchored cores deliberately return a closed error here; they
    /// retain their read-only/offline APIs but cannot resume v6 mutations.
    ///
    /// # Errors
    ///
    /// Returns a closed error unless a live runtime and anchored store agree.
    pub async fn prepare_mutation(
        &self,
        request: MutationRequest,
    ) -> Result<PreparedMutationLease, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.prepare_mutation_under_operation(request)
    }

    fn prepare_mutation_under_operation(
        &self,
        mut request: MutationRequest,
    ) -> Result<PreparedMutationLease, AppCoreError> {
        request.validate_invariants()?;
        let client = self.live_runtime_client()?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        let binding = self.mutation_binding_for(&identity);
        let security = self
            .mutation_security
            .as_ref()
            .ok_or(AppCoreError::MutationUnavailable)?;
        let ledger_identity = ledger_identity(binding, &request)?;
        let command = request.ledger_command()?;
        let mut store = self.store.lock().map_err(|_| AppCoreError::StateUnavailable)?;
        let permit = store
            .prepare_anchored_mutation_v7(security.secure.as_ref(), ledger_identity, command)
            .map_err(|_| AppCoreError::MutationUnavailable)?;
        let key = permit.record().idempotency_key().to_owned();
        if key != request.idempotency_key {
            let command_id = CanonicalId::parse(&key).map_err(|_| AppCoreError::MutationUnavailable)?;
            request.command_identity = CommandIdentity::new(command_id, key.clone())
                .map_err(|_| AppCoreError::MutationUnavailable)?;
            request.idempotency_key = key;
        }
        drop(store);
        Ok(PreparedMutationLease {
            runtime_identity: identity,
            gate_epoch: binding.gate_epoch,
            anchored_record: permit.record().clone(),
            request,
            finalized_root: None,
        })
    }

    fn transition_v7_under_operation(
        &self,
        lease: &mut PreparedMutationLease,
        transition: gocode_local_store::V7MutationTransition,
    ) -> Result<(), AppCoreError> {
        let command = lease
            .anchored_record
            .normalized_command()
            .ok_or(AppCoreError::MutationUnavailable)?;
        request_matches_anchored_command(&lease.request, command)?;
        let security = self
            .mutation_security
            .as_ref()
            .ok_or(AppCoreError::MutationUnavailable)?;
        let identity = ledger_identity(lease_ledger_binding(lease), &lease.request)?;
        let mut store = self.store.lock().map_err(|_| AppCoreError::StateUnavailable)?;
        lease.anchored_record = store
            .transition_anchored_mutation_v7(security.secure.as_ref(), identity, transition)
            .map_err(|_| AppCoreError::MutationUnavailable)?
            .record()
            .clone();
        drop(store);
        Ok(())
    }

    fn resend_v7_under_operation(
        &self,
        lease: &mut PreparedMutationLease,
        timestamp: u64,
    ) -> Result<(), AppCoreError> {
        let command = lease
            .anchored_record
            .normalized_command()
            .ok_or(AppCoreError::MutationUnavailable)?;
        request_matches_anchored_command(&lease.request, command)?;
        let security = self
            .mutation_security
            .as_ref()
            .ok_or(AppCoreError::MutationUnavailable)?;
        let identity = ledger_identity(lease_ledger_binding(lease), &lease.request)?;
        let mut store = self.store.lock().map_err(|_| AppCoreError::StateUnavailable)?;
        lease.anchored_record = store
            .resend_anchored_mutation_v7(security.secure.as_ref(), identity, timestamp)
            .map_err(|_| AppCoreError::MutationUnavailable)?
            .record()
            .clone();
        drop(store);
        Ok(())
    }

    fn mutation_binding_for(
        &self,
        identity: &replay::StableRuntimeIdentity,
    ) -> MutationAdmissionBinding {
        MutationAdmissionBinding {
            runtime_identity_digest: digest_runtime_identity(identity),
            principal_digest: digest_identity(b"principal", &identity.principal),
            gate_epoch: self.mutation_gate_epoch.load(Ordering::Acquire),
        }
    }
}

fn lease_ledger_binding(lease: &PreparedMutationLease) -> MutationAdmissionBinding {
    MutationAdmissionBinding {
        runtime_identity_digest: digest_runtime_identity(&lease.runtime_identity),
        principal_digest: digest_identity(b"principal", &lease.runtime_identity.principal),
        gate_epoch: lease.gate_epoch,
    }
}

fn digest_runtime_identity(identity: &replay::StableRuntimeIdentity) -> [u8; 32] {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/app-core/mutation-runtime-identity/v2\0");
    for value in [
        &identity.authority,
        &identity.lineage,
        &identity.profile_id,
        &identity.schema_hash,
        &identity.capability_digest,
    ] {
        digest.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize().into()
}

fn digest_identity(domain: &[u8], value: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/app-core/mutation-identity/v1\0");
    digest.update(domain);
    digest.update(value.as_bytes());
    digest.finalize().into()
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
