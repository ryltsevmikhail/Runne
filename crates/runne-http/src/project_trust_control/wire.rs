use runne_api::ProjectTrustControlSnapshot;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DecisionBody {
    pub action: String,
    pub expected_epoch: String,
    pub expected_revision: String,
    pub expected_project_version: String,
    pub expected_workspace_version: String,
    pub expected_root_admission_version: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SnapshotWire {
    project_id: String,
    project_name: String,
    project_version: String,
    workspace_id: String,
    workspace_name: String,
    workspace_version: String,
    status: &'static str,
    managed_deny_mask: u32,
    provenance: &'static str,
    epoch: String,
    revision: String,
    root_admission_version: Option<String>,
}

impl From<ProjectTrustControlSnapshot> for SnapshotWire {
    fn from(s: ProjectTrustControlSnapshot) -> Self {
        Self {
            project_id: s.project_id.to_string(),
            project_name: s.project_name,
            project_version: s.project_version.to_string(),
            workspace_id: s.workspace_id.to_string(),
            workspace_name: s.workspace_name,
            workspace_version: s.workspace_version.to_string(),
            status: match s.status {
                runne_api::ProjectTrustControlStatus::Untrusted => "untrusted",
                runne_api::ProjectTrustControlStatus::Trusted => "trusted",
                runne_api::ProjectTrustControlStatus::Managed => "managed",
            },
            managed_deny_mask: s.managed_deny_mask,
            provenance: match s.provenance {
                runne_api::ProjectTrustControlProvenance::Default => "default",
                runne_api::ProjectTrustControlProvenance::User => "user",
                runne_api::ProjectTrustControlProvenance::Managed => "managed",
            },
            epoch: s.epoch.to_string(),
            revision: s.revision.to_string(),
            root_admission_version: s.root_admission_version.map(|v| v.to_string()),
        }
    }
}
