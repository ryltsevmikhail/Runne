use std::sync::{Arc, Mutex};

use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_domain::id::EventLogLineageId;
use runne_domain::replay::ReplayScope;
use runne_domain::verification::backup::StreamInventory;
use runne_domain::verification::digest::VerificationDigest;
use runne_store::replay_store::ReplayStore;
use runne_store::verification::backup_store::InMemoryBackupStore;

use crate::vectors::{GAP_DIGEST, IDENTITIES, SOURCE_COMMIT};

#[test]
fn sourcecraft_556f_literals_are_canonical_and_runne_aliases_are_distinct() {
    assert_eq!(SOURCE_COMMIT, "556f09eb");
    for (canonical, alias) in IDENTITIES {
        assert!(canonical.starts_with("gocode") || canonical.starts_with("GOCODE"));
        assert!(alias.starts_with("runne") || alias.starts_with("RUNNE"));
        assert_ne!(canonical, alias);
    }
}

#[test]
fn replay_gap_vector_uses_the_sourcecraft_domain() {
    let scope = ReplayScope::Aggregate {
        aggregate_type: 2,
        aggregate_id: [5; 16],
    };
    let reference = ReplayStore::build_gap_range_ref(
        &EventLogLineageId::from_bytes([4; 16]),
        7,
        11,
        13,
        &scope,
        17,
        &[6; 32],
    );
    assert_eq!(reference.integrity().as_bytes(), &GAP_DIGEST);
}

#[test]
fn backup_archive_is_guarded_by_the_fixed_sourcecraft_prefix() {
    let guard = Arc::new(CaptureGuard::default());
    let store = InMemoryBackupStore::new(guard.clone());
    let manifest = store
        .create_backup(
            vec![StreamInventory {
                stream_name: "sourcecraft-stream".into(),
                event_count: 3,
                first_sequence: 1,
                last_sequence: 3,
            }],
            VerificationDigest::from_bytes([9; 32]),
        )
        .unwrap();
    let observed = guard.bytes.lock().unwrap().clone();
    assert_eq!(observed, store.archive_bytes(&manifest.backup_id).unwrap());
    assert!(observed.starts_with(b"GOCODE_SYNTHETIC_VERIFICATION_BACKUP_V1\0"));
    assert!(!observed.windows(6).any(|part| part == b"RUNNE_"));
}

#[derive(Default)]
struct CaptureGuard {
    bytes: Mutex<Vec<u8>>,
}

impl ProhibitedContentPort for CaptureGuard {
    fn inspect(
        &self,
        boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        assert_eq!(boundary, CanonicalContentBoundary::OutboundDelivery);
        *self.bytes.lock().unwrap() = bytes.to_vec();
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}
