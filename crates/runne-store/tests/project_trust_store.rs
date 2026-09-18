//! Real SQLite persistence invariants for the T1 project trust sidecar:
//! untrusted default, monotonic CAS revision, reopen durability,
//! fail-closed authority verification, and epoch-scoped ABA safety (F1).

use std::path::{Path, PathBuf};

use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
    SourceChannel, TrustPersistenceError, TrustToken,
};
use runne_store::ProjectTrustStore;
use tempfile::TempDir;

struct Sidecar {
    _root: TempDir,
    canonical: PathBuf,
}

impl Sidecar {
    fn new(name: &str) -> Self {
        let root = tempfile::Builder::new().prefix(name).tempdir().unwrap();
        let daemon = root.path().join("runne-daemon");
        std::fs::create_dir(&daemon).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let canonical = daemon.join("event-log.sqlite");
        Self {
            _root: root,
            canonical,
        }
    }

    fn path(&self) -> PathBuf {
        let mut name = self.canonical.as_os_str().to_owned();
        name.push(".project-trust");
        PathBuf::from(&name)
    }
}

const AUTHORITY: [u8; 16] = [0x11; 16];

fn project() -> ProjectTrustProjectId {
    ProjectTrustProjectId::from_bytes([0x22; 16])
}

#[test]
fn absent_project_reads_as_untrusted_default_bound_to_epoch() {
    let sidecar = Sidecar::new("trust-default");
    let store = ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).unwrap();
    let epoch = store.instance_epoch().unwrap();
    assert_ne!(epoch, 0, "instance epoch must be unpredictable non-zero");
    assert_eq!(
        store.load(project()).unwrap(),
        ProjectTrustRecord::untrusted_default(epoch)
    );
}

#[test]
fn revision_is_monotonic_and_cas_protected() {
    let sidecar = Sidecar::new("trust-cas");
    let store = ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).unwrap();
    let epoch = store.instance_epoch().unwrap();
    let first = store
        .commit(
            project(),
            ProjectTrustStatus::Trusted,
            0,
            TrustToken::new(epoch, 0),
        )
        .unwrap();
    assert_eq!(first.revision, 1);
    assert_eq!(first.instance_epoch, epoch);

    let second = store
        .commit(
            project(),
            ProjectTrustStatus::Trusted,
            0,
            TrustToken::new(epoch, 1),
        )
        .unwrap();
    assert_eq!(second.revision, 2);

    let stale = store.commit(
        project(),
        ProjectTrustStatus::Managed,
        0,
        TrustToken::new(epoch, 1),
    );
    assert_eq!(
        stale.unwrap_err(),
        TrustPersistenceError::Conflict {
            expected: 1,
            current: 2
        }
    );

    let third = store
        .commit(
            project(),
            ProjectTrustStatus::Managed,
            0,
            TrustToken::new(epoch, 2),
        )
        .unwrap();
    assert_eq!(third.revision, 3, "failed CAS must not consume a revision");
    assert_eq!(store.load(project()).unwrap().revision, 3);
}

#[test]
fn state_survives_reopen_with_same_epoch() {
    let sidecar = Sidecar::new("trust-reopen");
    let (first_epoch, revision) = {
        let store = ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).unwrap();
        let epoch = store.instance_epoch().unwrap();
        let record = store
            .commit(
                project(),
                ProjectTrustStatus::Managed,
                SourceChannel::FilesRead.mask_bit(),
                TrustToken::new(epoch, 0),
            )
            .unwrap();
        (epoch, record.revision)
    };
    let reopened = ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).unwrap();
    assert_eq!(
        reopened.instance_epoch().unwrap(),
        first_epoch,
        "epoch is durable and survives reopen"
    );
    let record = reopened.load(project()).unwrap();
    assert_eq!(record.revision, revision);
    assert_eq!(record.status, ProjectTrustStatus::Managed);
    assert_eq!(
        record.managed_deny_mask,
        SourceChannel::FilesRead.mask_bit()
    );
}

#[test]
fn wrong_authority_fails_closed_on_reopen() {
    let sidecar = Sidecar::new("trust-authority");
    {
        let store = ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).unwrap();
        store
            .commit(
                project(),
                ProjectTrustStatus::Trusted,
                0,
                TrustToken::new(store.instance_epoch().unwrap(), 0),
            )
            .unwrap();
    }
    let wrong = ProjectTrustStore::open(&sidecar.canonical, [0x33; 16]);
    assert!(wrong.is_err(), "mismatched authority must fail closed");
}

#[test]
fn tampered_identity_row_fails_closed_on_reopen() {
    let sidecar = Sidecar::new("trust-tamper");
    {
        let store = ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).unwrap();
        store
            .commit(
                project(),
                ProjectTrustStatus::Trusted,
                0,
                TrustToken::new(store.instance_epoch().unwrap(), 0),
            )
            .unwrap();
    }
    {
        // The CHECK constraints protect kind/version; authority bytes are
        // length-checked only, so a foreign 16-byte authority is the tamper
        // probe for the reopen verification path.
        let raw = rusqlite::Connection::open(sidecar.path()).unwrap();
        raw.execute(
            "UPDATE project_trust_schema SET authority_id = ?1 WHERE id = 1",
            rusqlite::params![[0x44u8; 16].as_slice()],
        )
        .unwrap();
    }
    assert!(
        ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).is_err(),
        "corrupted identity must fail closed"
    );
}

#[test]
fn deleted_sidecar_regrant_rejects_old_tokens_aba() {
    let sidecar = Sidecar::new("trust-aba");
    let old_token = {
        let store = ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).unwrap();
        let record = store
            .commit(
                project(),
                ProjectTrustStatus::Trusted,
                0,
                TrustToken::new(store.instance_epoch().unwrap(), 0),
            )
            .unwrap();
        record.token()
    };
    std::fs::remove_file(sidecar.path()).unwrap();
    let recreated = ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).unwrap();
    let new_epoch = recreated.instance_epoch().unwrap();
    assert_ne!(
        new_epoch, old_token.instance_epoch,
        "recreated sidecar must own a fresh unpredictable epoch"
    );
    let record = recreated.load(project()).unwrap();
    assert_eq!(
        record,
        ProjectTrustRecord::untrusted_default(new_epoch),
        "recreated sidecar reads as untrusted default in the new epoch"
    );
    // Re-grant Trusted at the same numeric revision 1: the old token must
    // still be rejected because its epoch is foreign.
    recreated
        .commit(
            project(),
            ProjectTrustStatus::Trusted,
            0,
            TrustToken::new(new_epoch, record.revision),
        )
        .unwrap();
    let regranted = recreated.load(project()).unwrap();
    assert_eq!(regranted.revision, 1);
    let old_cas = recreated.commit(
        project(),
        ProjectTrustStatus::Managed,
        0,
        TrustToken::new(old_token.instance_epoch, old_token.revision),
    );
    assert_eq!(
        old_cas.unwrap_err(),
        TrustPersistenceError::ForeignEpoch {
            expected_epoch: old_token.instance_epoch,
            current_epoch: new_epoch
        },
        "stale grants from a deleted sidecar must not write into the new one"
    );
}

#[test]
fn empty_sidecar_file_fails_closed() {
    let sidecar = Sidecar::new("trust-empty");
    std::fs::write(sidecar.path(), b"").unwrap();
    assert!(
        ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).is_err(),
        "a present but unclassifiable sidecar must fail closed, not re-create"
    );
}

#[test]
fn foreign_schema_sidecar_file_fails_closed() {
    let sidecar = Sidecar::new("trust-foreign");
    {
        let raw = rusqlite::Connection::open(sidecar.path()).unwrap();
        raw.execute_batch("CREATE TABLE other(a);").unwrap();
    }
    assert!(
        ProjectTrustStore::open(&sidecar.canonical, AUTHORITY).is_err(),
        "a sidecar with a foreign catalog must fail closed"
    );
}

#[test]
fn relative_canonical_path_fails_closed() {
    assert!(
        ProjectTrustStore::open(Path::new("relative/event-log.sqlite"), AUTHORITY).is_err(),
        "F4: only absolute canonical paths may open a sidecar"
    );
}
