// Forward profile rebind: migrate a stored stable activation binding to the
// current contract generation while preserving its authenticated identity.
//
// The stored binding's identity fields (authority_id, principal_id, lineage_id)
// are never rewritten. Rebinding is allowed only within the same profile_id and
// is authenticated by the daemon against its owner-private authority sidecar
// and Event Log lineage; the migrated record is written only after the signed
// ready frame, so any earlier failure leaves the previous binding intact.

/// Outcome of comparing a stored stable binding with the current launch profile.
#[derive(Clone, Debug, Eq, PartialEq)]
enum StableProfileMatch {
    /// Stored binding exactly matches the current profile.
    Exact,
    /// Identity preserved; profile fields rebind forward to the current profile.
    Rebind(StableRuntimeBindingV1),
}

fn stable_rebind_decision(
    stable: &StableRuntimeBindingV1,
    profile: &ProtectedRuntimeProfileV1,
) -> Result<StableProfileMatch, ProtectedBundledRuntimeError> {
    if stable.principal_id() != LOCAL_PRINCIPAL || stable.profile_id() != profile.profile_id() {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    if stable.profile_hash() == profile.profile_hash()
        && stable.capability_digest() == profile.capability_digest()
    {
        return Ok(StableProfileMatch::Exact);
    }
    StableRuntimeBindingV1::new(
        *stable.authority_id(),
        LOCAL_PRINCIPAL,
        *stable.lineage_id(),
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )
    .map(StableProfileMatch::Rebind)
    .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)
}

/// Shared compare-and-swap guard for the stable binding migration.
///
/// Returns the encoded record to write, or `None` when the on-disk record
/// already equals `next` (idempotent retry). Any other state fails closed.
fn migration_payload(
    existing: Option<StoredStableV1>,
    previous: &StableRuntimeBindingV1,
    next: &StableRuntimeBindingV1,
) -> Result<Option<Vec<u8>>, ProtectedBundledRuntimeError> {
    let previous_record = StoredStableV1::from_contract(previous);
    let next_record = StoredStableV1::from_contract(next);
    match existing {
        Some(existing) if existing == next_record => Ok(None),
        Some(existing) if existing == previous_record => {
            let encoded = serde_json::to_vec(&next_record)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            if encoded.is_empty() || encoded.len() as u64 > MAX_STATE_BYTES {
                return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
            }
            Ok(Some(encoded))
        }
        _ => Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
    }
}

#[cfg(unix)]
impl ActivationStateStore {
    /// Atomically replaces the stable binding with the daemon-authenticated
    /// record after a forward profile rebind.
    fn migrate_stable_exact(
        &self,
        previous: &StableRuntimeBindingV1,
        next: &StableRuntimeBindingV1,
        controls: &mut LaunchTestControls,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let encoded =
            migration_payload(self.read_record::<StoredStableV1>(STABLE_RECORD_FILE)?, previous, next)?;
        let Some(encoded) = encoded else {
            return Ok(());
        };
        let temporary_path = self
            .directory
            .join(format!(".{STABLE_RECORD_FILE}.{}.tmp", uuid::Uuid::now_v7()));
        let final_path = self.directory.join(STABLE_RECORD_FILE);
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary_path)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            file.write_all(&encoded)
                .and_then(|()| file.sync_all())
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            controls.checkpoint(ActivationCheckpoint::AfterFinalPinFileSync)?;
            drop(file);
            std::fs::rename(&temporary_path, &final_path)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            sync_directory(&self.directory)
        })();
        if temporary_path.exists() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        result
    }
}

#[cfg(windows)]
impl ActivationStateStore {
    /// Atomically replaces the stable binding with the daemon-authenticated
    /// record after a forward profile rebind.
    fn migrate_stable_exact(
        &self,
        previous: &StableRuntimeBindingV1,
        next: &StableRuntimeBindingV1,
        controls: &mut LaunchTestControls,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let encoded =
            migration_payload(self.read_record::<StoredStableV1>(STABLE_RECORD_FILE)?, previous, next)?;
        let Some(encoded) = encoded else {
            return Ok(());
        };
        let temporary = self
            .directory
            .join(format!(".{STABLE_RECORD_FILE}.{}.tmp", uuid::Uuid::now_v7()));
        let final_path = self.directory.join(STABLE_RECORD_FILE);
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            file.write_all(&encoded)
                .and_then(|()| file.sync_all())
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            controls.checkpoint(ActivationCheckpoint::AfterFinalPinFileSync)?;
            drop(file);
            std::fs::rename(&temporary, &final_path)
                .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
            validate_private_path(&final_path)
        })();
        if temporary.exists() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(test)]
mod rebind_decision_tests {
    use super::{StableProfileMatch, stable_rebind_decision};
    use runne_api::{ProtectedRuntimeProfileV1, StableRuntimeBindingV1};

    const PROFILE_ID: &str = "gocode-ui-client/3";

    fn uuid_v7(seed: u8) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        // UUIDv7: 48-bit unix-ms timestamp, version 7, variant 10.
        bytes[0] = 0x01;
        bytes[5] = seed;
        bytes[6] = 0x70;
        bytes[8] = 0x80 | (seed & 0x3f);
        bytes[15] = seed;
        bytes
    }

    fn profile(hash_seed: u8, digest_seed: u8) -> ProtectedRuntimeProfileV1 {
        ProtectedRuntimeProfileV1::new(
            "gocode-local-runtime/2".to_owned(),
            1,
            PROFILE_ID.to_owned(),
            [hash_seed; 32],
            [digest_seed; 32],
        )
        .expect("valid test profile")
    }

    fn binding(hash_seed: u8, digest_seed: u8) -> StableRuntimeBindingV1 {
        StableRuntimeBindingV1::new(
            uuid_v7(1),
            "local-owner",
            uuid_v7(2),
            PROFILE_ID.to_owned(),
            [hash_seed; 32],
            [digest_seed; 32],
        )
        .expect("valid test binding")
    }

    #[test]
    fn exact_match_needs_no_migration() {
        let profile = profile(7, 9);
        assert_eq!(
            stable_rebind_decision(&binding(7, 9), &profile).expect("decision"),
            StableProfileMatch::Exact
        );
    }

    #[test]
    fn stale_profile_hash_rebinds_forward_preserving_identity() {
        let profile = profile(7, 9);
        let stored = binding(3, 9);
        let StableProfileMatch::Rebind(rebound) =
            stable_rebind_decision(&stored, &profile).expect("decision")
        else {
            panic!("expected rebind");
        };
        assert_eq!(rebound.authority_id(), stored.authority_id());
        assert_eq!(rebound.lineage_id(), stored.lineage_id());
        assert_eq!(rebound.principal_id(), "local-owner");
        assert_eq!(rebound.profile_id(), PROFILE_ID);
        assert_eq!(rebound.profile_hash(), profile.profile_hash());
        assert_eq!(rebound.capability_digest(), profile.capability_digest());
    }

    #[test]
    fn stale_capability_digest_rebinds_forward() {
        let profile = profile(7, 9);
        assert!(matches!(
            stable_rebind_decision(&binding(7, 4), &profile).expect("decision"),
            StableProfileMatch::Rebind(_)
        ));
    }

    #[test]
    fn both_profile_fields_stale_rebind_forward() {
        let profile = profile(7, 9);
        assert!(matches!(
            stable_rebind_decision(&binding(3, 4), &profile).expect("decision"),
            StableProfileMatch::Rebind(_)
        ));
    }

    #[test]
    fn foreign_profile_id_is_rejected_without_rebind() {
        let profile = profile(7, 9);
        let stored = StableRuntimeBindingV1::new(
            uuid_v7(1),
            "local-owner",
            uuid_v7(2),
            "gocode-ui-client/2".to_owned(),
            [3; 32],
            [9; 32],
        )
        .expect("valid binding");
        assert!(stable_rebind_decision(&stored, &profile).is_err());
    }

    #[test]
    fn foreign_principal_is_rejected_without_rebind() {
        let profile = profile(7, 9);
        let stored = StableRuntimeBindingV1::new(
            uuid_v7(1),
            "not-the-owner",
            uuid_v7(2),
            PROFILE_ID.to_owned(),
            [3; 32],
            [9; 32],
        )
        .expect("valid binding");
        assert!(stable_rebind_decision(&stored, &profile).is_err());
    }
}
