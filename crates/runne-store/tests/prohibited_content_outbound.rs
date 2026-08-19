use std::sync::Arc;

use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::verification::export_port::{
    VerificationExporter, VerificationOutboundError,
};
use runne_domain::verification::backup::StreamInventory;
use runne_domain::verification::digest::VerificationDigest;
use runne_store::verification::backup_store::{BackupStoreError, InMemoryBackupStore};

const MARKER: &str = "task-seven-outbound-marker";

#[derive(Clone, Copy)]
enum GuardMode {
    Marker,
    Unavailable,
}

struct BoundaryGuard(GuardMode);

impl ProhibitedContentPort for BoundaryGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        match self.0 {
            GuardMode::Unavailable => Err(ContentGuardError::Unavailable),
            GuardMode::Marker
                if bytes
                    .windows(MARKER.len())
                    .any(|window| window == MARKER.as_bytes()) =>
            {
                Ok(ContentDisposition::Prohibited { policy_epoch: 2 })
            }
            GuardMode::Marker => Ok(ContentDisposition::Allowed { policy_epoch: 2 }),
        }
    }
}

fn assert_export_denied(mode: GuardMode) {
    let exporter = VerificationExporter::new(Arc::new(BoundaryGuard(mode)));
    let result =
        exporter.export_run_json(uuid::Uuid::now_v7(), uuid::Uuid::now_v7(), MARKER, None, 0);

    assert_eq!(result, Err(VerificationOutboundError::PolicyDenied));
}

fn assert_backup_denied(mode: GuardMode) {
    let store = InMemoryBackupStore::new(Arc::new(BoundaryGuard(mode)));
    let result = store.create_backup(
        vec![StreamInventory {
            stream_name: MARKER.into(),
            event_count: 1,
            first_sequence: 1,
            last_sequence: 1,
        }],
        VerificationDigest::from_bytes([1; 32]),
    );

    assert!(matches!(result, Err(BackupStoreError::PolicyDenied)));
    assert_eq!(store.archive_count(), 0);
}

#[test]
fn prohibited_export_and_synthetic_backup_emit_zero_bytes() {
    assert_export_denied(GuardMode::Marker);
    assert_backup_denied(GuardMode::Marker);
}

#[test]
fn unavailable_export_and_synthetic_backup_emit_zero_bytes() {
    assert_export_denied(GuardMode::Unavailable);
    assert_backup_denied(GuardMode::Unavailable);
}
