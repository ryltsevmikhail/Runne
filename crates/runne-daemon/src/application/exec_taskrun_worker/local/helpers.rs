use super::*;
use runne_platform::process_managed_area::{LinuxManagedAreaRoot, ManagedAreaBinding};

pub(super) const APPROVAL_ACTION: &str = "local_command.execute";
pub(super) const APPROVAL_LIFETIME_MS: i64 = 86_400_000;

pub(super) fn require_managed_area_support(
    taskrun_id: runne_domain::id::TaskRunId,
) -> Result<(), AutomaticTaskRunError> {
    let root = LinuxManagedAreaRoot::open_current_cgroup()
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let binding = ManagedAreaBinding::new(
        *taskrun_id.as_bytes(),
        *uuid::Uuid::now_v7().as_bytes(),
        *uuid::Uuid::now_v7().as_bytes(),
    )
    .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    root.create_area(binding)
        .and_then(|area| area.remove_empty())
        .map_err(|_| AutomaticTaskRunError::Unavailable)
}

pub(super) fn digest_file(file: &std::fs::File) -> Result<[u8; 32], AutomaticTaskRunError> {
    let mut input = file
        .try_clone()
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 32 * 1024];
    let mut total = 0usize;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        if total > 64 * 1024 * 1024 {
            return Err(AutomaticTaskRunError::RejectedBeforeEffect);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

pub(super) struct ApprovalDigestInput {
    pub(super) command: [u8; 32],
    pub(super) executable: [u8; 32],
    pub(super) project: [u8; 16],
    pub(super) workspace: u64,
    pub(super) root: u64,
    pub(super) root_id: [u8; 32],
    pub(super) trust: TrustToken,
    pub(super) source_policy: u64,
    pub(super) command_policy: u64,
}

pub(super) fn approval_digest(input: ApprovalDigestInput) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne-local-command-approval-v1\0");
    hash.update(input.command);
    hash.update(input.executable);
    hash.update(input.project);
    hash.update(input.workspace.to_be_bytes());
    hash.update(input.root.to_be_bytes());
    hash.update(input.root_id);
    hash.update(input.trust.instance_epoch.to_be_bytes());
    hash.update(input.trust.revision.to_be_bytes());
    hash.update(input.source_policy.to_be_bytes());
    hash.update(input.command_policy.to_be_bytes());
    hash.finalize().into()
}

pub(super) fn stable_id(taskrun: &[u8; 16], label: &[u8]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"runne-local-command-id-v1\0");
    hash.update(taskrun);
    hash.update(label);
    let digest = hash.finalize();
    let mut id: [u8; 16] = digest[..16].try_into().expect("fixed digest size");
    id[6] = (id[6] & 0x0f) | 0x70;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

pub(super) fn approval_resource(
    taskrun_id: runne_domain::id::TaskRunId,
    workspace_id: runne_domain::id::WorkspaceId,
) -> String {
    format!("taskrun:{taskrun_id}:workspace:{workspace_id}")
}

pub(super) fn approval_review_summary(
    command: &runne_domain::task_run::TaskRunLocalCommand,
) -> Result<String, AutomaticTaskRunError> {
    approval_review_summary_inner(command, None)
}

pub(super) fn approval_review_summary_for_scope(
    command: &runne_domain::task_run::TaskRunLocalCommand,
    scope: &runne_application::permission_modes::CompositeEffectScope,
) -> Result<String, AutomaticTaskRunError> {
    approval_review_summary_inner(command, Some(scope))
}

fn approval_review_summary_inner(
    command: &runne_domain::task_run::TaskRunLocalCommand,
    scope: Option<&runne_application::permission_modes::CompositeEffectScope>,
) -> Result<String, AutomaticTaskRunError> {
    let executable = match command.executable() {
        runne_domain::task_run::TaskRunExecutable::WorkspaceRelative(path) => {
            serde_json::json!({"workspace_relative": path})
        }
        runne_domain::task_run::TaskRunExecutable::SystemProgram(catalog_id) => {
            serde_json::json!({"system_catalog_id": catalog_id})
        }
    };
    let environment: Vec<_> = command
        .env()
        .iter()
        .map(|(key, _)| serde_json::json!({"key": key, "value": "[REDACTED]"}))
        .collect();
    let mut details = serde_json::json!({
        "kind": "structured_local_command",
        "executable": executable,
        "cwd": command.cwd(),
        "argv": command.argv(),
        "environment": environment,
        "environment_values_are_redacted": true,
    });
    if let Some(scope) = scope {
        let network = match scope.network {
            runne_application::permission_modes::NetworkScope::None => "disabled",
            runne_application::permission_modes::NetworkScope::BroadSameUser => "broad_same_user",
            runne_application::permission_modes::NetworkScope::Brokered { .. } => "brokered",
        };
        let descendants = match scope.children {
            runne_application::permission_modes::ChildDelegationScope::None => "none".to_owned(),
            runne_application::permission_modes::ChildDelegationScope::MaxDepth(depth) => {
                format!("max_depth_{depth}")
            }
            runne_application::permission_modes::ChildDelegationScope::Unbounded => {
                "unbounded".to_owned()
            }
        };
        let filesystem = match &scope.filesystem.posture {
            runne_application::permission_modes::FilesystemPosture::None => "none",
            runne_application::permission_modes::FilesystemPosture::BoundedRoots(_) => {
                "bounded_roots"
            }
            runne_application::permission_modes::FilesystemPosture::BroadSameUser => {
                "broad_same_user"
            }
        };
        details["permission_scope"] = serde_json::json!({
            "filesystem": filesystem,
            "filesystem_rights": scope.filesystem.permissions.iter().map(|right| match right {
                runne_application::permission_modes::FilesystemPermission::Read => "read",
                runne_application::permission_modes::FilesystemPermission::Create => "create",
                runne_application::permission_modes::FilesystemPermission::Write => "write",
                runne_application::permission_modes::FilesystemPermission::Delete => "delete",
            }).collect::<Vec<_>>(),
            "network": network,
            "descendants": descendants,
            "runtime_limit_ms": scope.lifetime_ms,
        });
    }
    let rendered =
        serde_json::to_string(&details).map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    if rendered.len() > 4096 {
        return Err(AutomaticTaskRunError::RejectedBeforeEffect);
    }
    Ok(rendered)
}

pub(super) fn map_root_error(
    error: runne_platform_desktop::RootHandleBrokerError,
) -> AutomaticTaskRunError {
    match error {
        runne_platform_desktop::RootHandleBrokerError::Rejected => {
            AutomaticTaskRunError::RejectedBeforeEffect
        }
        runne_platform_desktop::RootHandleBrokerError::Unavailable => {
            AutomaticTaskRunError::Unavailable
        }
    }
}

pub(super) fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
