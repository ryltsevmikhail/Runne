use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use runne_api::ApiPrincipalId;
use runne_application::permission_modes::{PermissionMode, PermissionScope, PresetVersion};
use runne_application::ports::RuntimeAuthorityId;
use runne_application::project_trust::{ProjectTrustRecord, ProjectTrustStatus};
use runne_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use serde::{Deserialize, Serialize};

use super::super::hex;
use crate::store::permission_modes::model::NativeModeConfirmationRequestV2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    pub version: u8,
    pub case: String,
    pub nested: String,
    pub writer_pid: u32,
    pub recovered_pid: Option<u32>,
    pub authority: [u8; 16],
    pub lineage: String,
    pub project: String,
    pub workspace: String,
    pub principal: String,
    pub command: String,
    pub key: String,
    pub mode: String,
    pub preset: u16,
    pub expected_revision: u64,
    pub expires: Option<i64>,
    pub request_digest: [u8; 32],
    pub challenge: [u8; 16],
    pub binding_digest: [u8; 32],
    pub session: [u8; 16],
    pub launch_authority: [u8; 16],
    pub desktop_instance: [u8; 16],
    pub daemon_instance: [u8; 16],
    pub launch_generation: u64,
    pub key_epoch: u64,
    pub challenge_expires: i64,
    pub trust_epoch: u64,
    pub trust_revision: u64,
    pub trust_mask: u32,
    pub trust_status: String,
    pub receipt: Option<Receipt>,
}

// Complete public receipt representation, never a verification proof or nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub command: String,
    pub key: String,
    pub intent: [u8; 32],
    pub authority: String,
    pub principal: String,
    pub workspace: String,
    pub mode: String,
    pub preset: u16,
    pub revision: u64,
    pub expires: Option<i64>,
    pub history: Vec<u8>,
}

impl Checkpoint {
    pub fn request(&self) -> NativeModeConfirmationRequestV2 {
        assert_eq!(self.mode, "RiskBased");
        assert_eq!(self.preset, 1);
        assert_eq!(self.expected_revision, 0);
        let command: CommandId = self.command.parse().unwrap();
        let workspace_id: WorkspaceId = self.workspace.parse().unwrap();
        let _: ProjectId = self.project.parse().unwrap();
        let request = NativeModeConfirmationRequestV2 {
            command_id: command,
            idempotency_key: IdempotencyKey::new(self.key.clone()).unwrap(),
            scope: PermissionScope {
                runtime_authority_id: RuntimeAuthorityId(hex(&self.authority)),
                principal_id: ApiPrincipalId::new(self.principal.clone()).unwrap(),
                workspace_id,
            },
            requested_mode: PermissionMode::RiskBased,
            preset_version: PresetVersion::V1,
            expected_authorization_revision: self.expected_revision,
            expires_at_unix_ms: self.expires,
        };
        assert_eq!(
            request.public_request_digest().as_bytes(),
            &self.request_digest
        );
        request
    }

    pub fn trust_record(&self) -> ProjectTrustRecord {
        assert_eq!(self.trust_status, "Trusted");
        assert!(self.trust_epoch > 0 && self.trust_revision > 0);
        ProjectTrustRecord {
            status: ProjectTrustStatus::Trusted,
            instance_epoch: self.trust_epoch,
            revision: self.trust_revision,
            managed_deny_mask: self.trust_mask,
        }
    }

    pub fn daemon(&self, root: &Path) -> PathBuf {
        let mut components = Path::new(&self.nested).components();
        assert!(matches!(components.next(), Some(Component::Normal(_))));
        assert!(components.next().is_none());
        let nested = root.join(&self.nested);
        checked_dir(&nested);
        let runtime = nested.join("runtime");
        checked_dir(&runtime);
        let daemon = runtime.join("daemon");
        checked_dir(&daemon);
        assert!(std::fs::canonicalize(&daemon).unwrap().starts_with(root));
        daemon
    }
}

fn checked_dir(path: &Path) {
    let info = std::fs::symlink_metadata(path).unwrap();
    assert!(info.is_dir() && !info.file_type().is_symlink());
    assert_eq!(std::fs::canonicalize(path).unwrap(), path);
}

pub(super) fn regular(path: &Path) {
    let info = std::fs::symlink_metadata(path).unwrap();
    assert!(info.is_file() && !info.file_type().is_symlink());
    assert_eq!(std::fs::canonicalize(path).unwrap(), path);
}

pub(super) fn write(root: &Path, name: &str, value: &Checkpoint) {
    use std::os::unix::fs::OpenOptionsExt;
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= 16 * 1024);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.flush().unwrap();
    file.sync_all().unwrap();
}

pub(super) fn read(root: &Path, name: &str, case: &str) -> Checkpoint {
    let path = root.join(name);
    regular(&path);
    let file = std::fs::File::open(path).unwrap();
    assert!(file.metadata().unwrap().len() <= 16 * 1024);
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 16 * 1024);
    let value: Checkpoint = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value.version, 1);
    assert_eq!(value.case, case);
    assert_eq!(value.receipt.is_some(), case == "committed");
    assert!(value.writer_pid > 0);
    assert_ne!(value.challenge, [0; 16]);
    runne_domain::id::validate_uuid_v7_bytes(&value.authority).unwrap();
    runne_domain::id::validate_uuid_v7_bytes(&value.session).unwrap();
    let _: runne_domain::id::EventLogLineageId = value.lineage.parse().unwrap();
    value.request();
    value.trust_record();
    value.daemon(root);
    value
}
