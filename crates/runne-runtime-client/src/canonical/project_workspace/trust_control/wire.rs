use serde::{Deserialize, Serialize};

use super::types::{
    ProjectTrustControlRequestDto, ProjectTrustControlSnapshotDto, ProjectTrustStatusDto,
};
use crate::canonical::{CanonicalId, RuntimeApiError, RuntimeApiErrorKind};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SnapshotWire {
    project_id: CanonicalId,
    project_name: String,
    project_version: String,
    workspace_id: CanonicalId,
    workspace_name: String,
    workspace_version: String,
    status: String,
    managed_deny_mask: u32,
    provenance: String,
    epoch: String,
    revision: String,
    root_admission_version: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DecisionWire {
    action: &'static str,
    expected_epoch: String,
    expected_revision: String,
    expected_project_version: String,
    expected_workspace_version: String,
    expected_root_admission_version: Option<String>,
}

impl From<&ProjectTrustControlRequestDto> for DecisionWire {
    fn from(r: &ProjectTrustControlRequestDto) -> Self {
        Self {
            action: match r.decision {
                super::types::ProjectTrustDecisionDto::ConfirmProject => "confirm_project",
                super::types::ProjectTrustDecisionDto::RevokeProject => "revoke_project",
            },
            expected_epoch: r.expected_epoch.to_string(),
            expected_revision: r.expected_revision.to_string(),
            expected_project_version: r.expected_project_version.to_string(),
            expected_workspace_version: r.expected_workspace_version.to_string(),
            expected_root_admission_version: r
                .expected_root_admission_version
                .map(|v| v.to_string()),
        }
    }
}

impl TryFrom<SnapshotWire> for ProjectTrustControlSnapshotDto {
    type Error = RuntimeApiError;
    fn try_from(w: SnapshotWire) -> Result<Self, Self::Error> {
        let number = |v: String| {
            let parsed = v
                .parse::<u64>()
                .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
            (parsed.to_string() == v)
                .then_some(parsed)
                .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
        };
        let status = match w.status.as_str() {
            "untrusted" => ProjectTrustStatusDto::Untrusted,
            "trusted" => ProjectTrustStatusDto::Trusted,
            "managed" => ProjectTrustStatusDto::Managed,
            _ => return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)),
        };
        let provenance_valid = matches!(w.provenance.as_str(), "default" | "user" | "managed")
            && (w.provenance == "managed"
                || (w.provenance == "default" && status == ProjectTrustStatusDto::Untrusted)
                || (w.provenance == "user" && status != ProjectTrustStatusDto::Managed));
        if !provenance_valid {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        if runne_api::ProjectWorkspaceDisplayNameInput::new(w.project_name.clone()).is_err()
            || runne_api::ProjectWorkspaceDisplayNameInput::new(w.workspace_name.clone()).is_err()
            || (w.status == "managed" && w.provenance != "managed")
            || (w.managed_deny_mask != 0 && w.provenance != "managed")
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        let project_version = number(w.project_version)?;
        let workspace_version = number(w.workspace_version)?;
        let epoch = number(w.epoch)?;
        if project_version == 0 || workspace_version == 0 || epoch == 0 {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        let root_admission_version = w.root_admission_version.map(number).transpose()?;
        if root_admission_version.is_some_and(|v| v == 0 || v > workspace_version) {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        let revision = number(w.revision)?;
        let consistent = match w.provenance.as_str() {
            "default" => {
                status == ProjectTrustStatusDto::Untrusted
                    && revision == 0
                    && w.managed_deny_mask == 0
            }
            "user" => {
                revision > 0 && status != ProjectTrustStatusDto::Managed && w.managed_deny_mask == 0
            }
            "managed" => status == ProjectTrustStatusDto::Managed || w.managed_deny_mask != 0,
            _ => false,
        };
        if !consistent {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(Self {
            project_id: w.project_id,
            project_name: w.project_name,
            project_version,
            workspace_id: w.workspace_id,
            workspace_name: w.workspace_name,
            workspace_version,
            status,
            managed_deny_mask: w.managed_deny_mask,
            provenance: w.provenance,
            epoch,
            revision,
            root_admission_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(status: &str, provenance: &str, revision: &str) -> SnapshotWire {
        SnapshotWire {
            project_id: CanonicalId::parse("01890e00-0000-7000-8000-000000000001").unwrap(),
            project_name: "synthetic project".into(),
            project_version: "1".into(),
            workspace_id: CanonicalId::parse("01890e00-0000-7000-8000-000000000002").unwrap(),
            workspace_name: "synthetic workspace".into(),
            workspace_version: "2".into(),
            status: status.into(),
            managed_deny_mask: 0,
            provenance: provenance.into(),
            epoch: "1".into(),
            revision: revision.into(),
            root_admission_version: Some("1".into()),
        }
    }

    #[test]
    fn accepts_user_trusted_and_revoked_snapshots_and_rejects_bad_provenance() {
        assert_eq!(
            ProjectTrustControlSnapshotDto::try_from(wire("trusted", "user", "1"))
                .unwrap()
                .status(),
            ProjectTrustStatusDto::Trusted
        );
        assert_eq!(
            ProjectTrustControlSnapshotDto::try_from(wire("untrusted", "user", "2"))
                .unwrap()
                .status(),
            ProjectTrustStatusDto::Untrusted
        );
        assert!(ProjectTrustControlSnapshotDto::try_from(wire("trusted", "default", "0")).is_err());
        assert!(ProjectTrustControlSnapshotDto::try_from(wire("managed", "user", "2")).is_err());
    }
}
