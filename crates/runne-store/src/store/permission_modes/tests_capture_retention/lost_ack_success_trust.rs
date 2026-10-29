//! Original fresh trust sidecar identity and record continuity, never recreation.
use super::super::super::fixture::Fixture;
use crate::ProjectTrustStore;
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalTrust {
    canonical: PathBuf,
    project: [u8; 16],
    identity: [u64; 2],
    epoch: u64,
    revision: u64,
    mask: u32,
}
impl OriginalTrust {
    pub(super) fn of(f: &Fixture) -> Self {
        let record = f.trust.load(f.trust_id()).unwrap();
        assert_eq!(record.status, ProjectTrustStatus::Trusted);
        assert!(record.revision > 0 && record.instance_epoch > 0);
        let canonical = f.root.path().join("runtime/daemon/trust.sqlite");
        let sidecar = canonical.with_file_name("trust.sqlite.project-trust");
        let m = std::fs::symlink_metadata(sidecar).unwrap();
        assert!(m.is_file());
        Self {
            canonical,
            project: *f.project.as_bytes(),
            identity: [m.dev(), m.ino()],
            epoch: record.instance_epoch,
            revision: record.revision,
            mask: record.managed_deny_mask,
        }
    }
    pub(super) fn check(&self, root: &Path, authority: [u8; 16]) {
        assert!(self.canonical.starts_with(root));
        let sidecar = self.canonical.with_file_name("trust.sqlite.project-trust");
        // Pin an existing non-symlink file BEFORE the create-capable public open.
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(0o400_000)
            .open(&sidecar)
            .unwrap();
        let m = held.metadata().unwrap();
        assert!(m.is_file());
        assert_eq!([m.dev(), m.ino()], self.identity);
        let check_path = || {
            let m = std::fs::symlink_metadata(&sidecar).unwrap();
            assert!(m.is_file());
            assert_eq!([m.dev(), m.ino()], self.identity);
        };
        check_path();
        let trust = ProjectTrustStore::open(&self.canonical, authority).unwrap();
        let id = ProjectTrustProjectId::from_bytes(self.project);
        assert!(trust.has_explicit_record(id).unwrap());
        let record = trust.load(id).unwrap();
        assert_eq!(record.status, ProjectTrustStatus::Trusted);
        assert_eq!(
            (
                record.token().instance_epoch,
                record.token().revision,
                record.managed_deny_mask
            ),
            (self.epoch, self.revision, self.mask)
        );
        check_path();
        drop(trust);
        check_path();
        drop(held);
    }
}
