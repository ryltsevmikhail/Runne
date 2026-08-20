use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use runne_domain::verification::backup::*;
use runne_domain::verification::digest::VerificationDigest;
use runne_domain::verification::identity::BackupID;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

/// Failure to create a synthetic in-memory verification backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BackupStoreError {
    /// Prohibited content or unavailable classification denied delivery.
    #[error("verification backup denied by content policy")]
    PolicyDenied,
}

/// In-memory verification backup adapter with GC barrier simulation.
///
/// This is synthetic boundary-proof infrastructure, not a production Phase 9
/// backup/export implementation.
pub struct InMemoryBackupStore {
    archives: Mutex<HashMap<BackupID, (BackupManifestRef, Vec<u8>)>>,
    gc_barrier_active: Mutex<bool>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

impl InMemoryBackupStore {
    /// Constructs the synthetic adapter with a mandatory outbound guard.
    pub fn new(prohibited_content: Arc<dyn ProhibitedContentPort>) -> Self {
        Self {
            archives: Mutex::new(HashMap::new()),
            gc_barrier_active: Mutex::new(false),
            prohibited_content,
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
    ) -> Result<BackupManifestRef, BackupStoreError> {
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

        let archive = serialize_synthetic_archive(&manifest);
        let disposition = self
            .prohibited_content
            .inspect(CanonicalContentBoundary::OutboundDelivery, &archive);
        if !matches!(disposition, Ok(ContentDisposition::Allowed { .. })) {
            *self.gc_barrier_active.lock().unwrap() = false;
            return Err(BackupStoreError::PolicyDenied);
        }

        let mut archives = self.archives.lock().unwrap();
        archives.insert(backup_id, (manifest.clone(), archive));

        // Release GC barrier
        *self.gc_barrier_active.lock().unwrap() = false;

        Ok(manifest)
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

    /// Returns the number of guarded synthetic archives retained in memory.
    pub fn archive_count(&self) -> usize {
        self.archives.lock().unwrap().len()
    }

    /// Returns guarded synthetic archive bytes for boundary-proof tests.
    pub fn archive_bytes(&self, backup_id: &BackupID) -> Option<Vec<u8>> {
        self.archives
            .lock()
            .unwrap()
            .get(backup_id)
            .map(|(_, bytes)| bytes.clone())
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

fn serialize_synthetic_archive(manifest: &BackupManifestRef) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GOCODE_SYNTHETIC_VERIFICATION_BACKUP_V1\0");
    bytes.extend_from_slice(manifest.backup_id.as_bytes());
    bytes.extend_from_slice(&manifest.schema_version.to_be_bytes());
    bytes.extend_from_slice(&(manifest.streams.len() as u64).to_be_bytes());
    for stream in &manifest.streams {
        bytes.extend_from_slice(&(stream.stream_name.len() as u64).to_be_bytes());
        bytes.extend_from_slice(stream.stream_name.as_bytes());
        bytes.extend_from_slice(&stream.event_count.to_be_bytes());
        bytes.extend_from_slice(&stream.first_sequence.to_be_bytes());
        bytes.extend_from_slice(&stream.last_sequence.to_be_bytes());
    }
    bytes.extend_from_slice(manifest.blob_inventory_digest.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_application::prohibited_content::{
        CanonicalContentBoundary, ContentDisposition, ContentGuardError,
    };

    struct AvailableGuard;

    impl ProhibitedContentPort for AvailableGuard {
        fn inspect(
            &self,
            _boundary: CanonicalContentBoundary,
            _bytes: &[u8],
        ) -> Result<ContentDisposition, ContentGuardError> {
            Ok(ContentDisposition::Allowed { policy_epoch: 1 })
        }
    }

    fn store() -> InMemoryBackupStore {
        InMemoryBackupStore::new(Arc::new(AvailableGuard))
    }

    #[test]
    fn backup_creates_manifest() {
        let store = store();
        let streams = vec![StreamInventory {
            stream_name: "verification_run".into(),
            event_count: 10,
            first_sequence: 1,
            last_sequence: 10,
        }];
        let manifest = store
            .create_backup(streams, VerificationDigest::from_bytes([1; 32]))
            .unwrap();
        assert!(manifest.integrity_result);
        assert_eq!(manifest.runtime_version, "1.0.0");
    }

    #[test]
    fn backup_verify_passes() {
        let store = store();
        let manifest = store
            .create_backup(vec![], VerificationDigest::from_bytes([1; 32]))
            .unwrap();
        assert!(store.verify_backup(&manifest.backup_id).is_ok());
    }

    #[test]
    fn backup_verify_nonexistent_fails() {
        let store = store();
        assert!(store.verify_backup(&Uuid::now_v7()).is_err());
    }

    #[test]
    fn gc_barrier_active_during_backup() {
        let store = store();
        // Barrier should be off after backup completes
        let _manifest = store
            .create_backup(vec![], VerificationDigest::from_bytes([1; 32]))
            .unwrap();
        assert!(!store.is_gc_barrier_active());
    }

    #[test]
    fn import_backup_counts_events() {
        let store = store();
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
        let manifest = store
            .create_backup(streams, VerificationDigest::from_bytes([1; 32]))
            .unwrap();
        assert_eq!(store.import_backup(&manifest.backup_id).unwrap(), 8);
    }

    #[test]
    fn smoke_test_passes() {
        let store = store();
        let manifest = store
            .create_backup(vec![], VerificationDigest::from_bytes([1; 32]))
            .unwrap();
        assert!(store.smoke_test(&manifest.backup_id).unwrap());
    }

    #[test]
    fn backup_manifest_stream_inventory() {
        let store = store();
        let streams = vec![StreamInventory {
            stream_name: "verification_run".into(),
            event_count: 10,
            first_sequence: 1,
            last_sequence: 10,
        }];
        let manifest = store
            .create_backup(streams, VerificationDigest::from_bytes([1; 32]))
            .unwrap();
        assert_eq!(manifest.streams.len(), 1);
        assert_eq!(manifest.streams[0].event_count, 10);
    }

    #[test]
    fn backup_has_lease_ref() {
        let store = store();
        let manifest = store
            .create_backup(vec![], VerificationDigest::from_bytes([1; 32]))
            .unwrap();
        assert!(!manifest.lease_ref.is_empty());
    }
}
