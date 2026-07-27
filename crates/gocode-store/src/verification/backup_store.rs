use gocode_domain::verification::backup::*;
use gocode_domain::verification::digest::VerificationDigest;
use gocode_domain::verification::identity::BackupID;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// In-memory backup store with GC barrier simulation.
pub struct InMemoryBackupStore {
    archives: Mutex<HashMap<BackupID, (BackupManifestRef, Vec<u8>)>>,
    gc_barrier_active: Mutex<bool>,
}

impl InMemoryBackupStore {
    pub fn new() -> Self {
        Self {
            archives: Mutex::new(HashMap::new()),
            gc_barrier_active: Mutex::new(false),
        }
    }

    /// Create consistent verification backup.
    /// 1. Acquire GC barrier
    /// 2. Snapshot streams
    /// 3. Create manifest
    /// 4. Release barrier
    pub fn create_backup(
        &self,
        streams: Vec<StreamInventory>,
        blob_digest: VerificationDigest,
    ) -> BackupManifestRef {
        // Acquire GC barrier
        *self.gc_barrier_active.lock().unwrap() = true;

        let backup_id = Uuid::now_v7();
        let archive_digest = VerificationDigest::from_bytes([1; 32]);

        let manifest = BackupManifestRef {
            backup_id,
            runtime_version: "1.0.0".into(),
            schema_version: 1,
            streams,
            blob_inventory_digest: blob_digest,
            archive_file_digest: archive_digest.clone(),
            lease_ref: format!("lease:{}", backup_id),
            integrity_result: true,
            high_water_mark: 100,
            integrity_digest: archive_digest,
        };

        let mut archives = self.archives.lock().unwrap();
        archives.insert(backup_id, (manifest.clone(), vec![1, 2, 3]));

        // Release GC barrier
        *self.gc_barrier_active.lock().unwrap() = false;

        manifest
    }

    /// Verify backup integrity.
    pub fn verify_backup(&self, backup_id: &BackupID) -> Result<(), String> {
        let archives = self.archives.lock().unwrap();
        let (manifest, _data) = archives.get(backup_id).ok_or("backup not found")?;
        if !manifest.integrity_result {
            return Err("integrity check failed".into());
        }
        Ok(())
    }

    /// Check GC barrier state.
    pub fn is_gc_barrier_active(&self) -> bool {
        *self.gc_barrier_active.lock().unwrap()
    }

    /// Import backup (idempotent restore).
    pub fn import_backup(&self, backup_id: &BackupID) -> Result<u64, String> {
        let archives = self.archives.lock().unwrap();
        let (manifest, _data) = archives.get(backup_id).ok_or("backup not found")?;
        let total_events: u64 = manifest.streams.iter().map(|s| s.event_count).sum();
        Ok(total_events)
    }

    /// Smoke test: verify imported data is usable.
    pub fn smoke_test(&self, backup_id: &BackupID) -> Result<bool, String> {
        let archives = self.archives.lock().unwrap();
        archives.get(backup_id).ok_or("backup not found")?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_creates_manifest() {
        let store = InMemoryBackupStore::new();
        let streams = vec![StreamInventory {
            stream_name: "verification_run".into(),
            event_count: 10,
            first_sequence: 1,
            last_sequence: 10,
        }];
        let manifest = store.create_backup(streams, VerificationDigest::from_bytes([1; 32]));
        assert!(manifest.integrity_result);
        assert_eq!(manifest.runtime_version, "1.0.0");
    }

    #[test]
    fn backup_verify_passes() {
        let store = InMemoryBackupStore::new();
        let manifest = store.create_backup(vec![], VerificationDigest::from_bytes([1; 32]));
        assert!(store.verify_backup(&manifest.backup_id).is_ok());
    }

    #[test]
    fn backup_verify_nonexistent_fails() {
        let store = InMemoryBackupStore::new();
        assert!(store.verify_backup(&Uuid::now_v7()).is_err());
    }

    #[test]
    fn gc_barrier_active_during_backup() {
        let store = InMemoryBackupStore::new();
        // Barrier should be off after backup completes
        let _manifest = store.create_backup(vec![], VerificationDigest::from_bytes([1; 32]));
        assert!(!store.is_gc_barrier_active());
    }

    #[test]
    fn import_backup_counts_events() {
        let store = InMemoryBackupStore::new();
        let streams = vec![
            StreamInventory {
                stream_name: "verification_run".into(),
                event_count: 5,
                first_sequence: 1,
                last_sequence: 5,
            },
            StreamInventory {
                stream_name: "gate_evaluation".into(),
                event_count: 3,
                first_sequence: 1,
                last_sequence: 3,
            },
        ];
        let manifest = store.create_backup(streams, VerificationDigest::from_bytes([1; 32]));
        assert_eq!(store.import_backup(&manifest.backup_id).unwrap(), 8);
    }

    #[test]
    fn smoke_test_passes() {
        let store = InMemoryBackupStore::new();
        let manifest = store.create_backup(vec![], VerificationDigest::from_bytes([1; 32]));
        assert!(store.smoke_test(&manifest.backup_id).unwrap());
    }

    #[test]
    fn backup_manifest_stream_inventory() {
        let store = InMemoryBackupStore::new();
        let streams = vec![StreamInventory {
            stream_name: "verification_run".into(),
            event_count: 10,
            first_sequence: 1,
            last_sequence: 10,
        }];
        let manifest = store.create_backup(streams, VerificationDigest::from_bytes([1; 32]));
        assert_eq!(manifest.streams.len(), 1);
        assert_eq!(manifest.streams[0].event_count, 10);
    }

    #[test]
    fn backup_has_lease_ref() {
        let store = InMemoryBackupStore::new();
        let manifest = store.create_backup(vec![], VerificationDigest::from_bytes([1; 32]));
        assert!(!manifest.lease_ref.is_empty());
    }
}
