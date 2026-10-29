use crate::application::root_handle_admission::RootAdmissionGateway;
use runne_store::store::taskrun_tool_invocation::ToolInvocationBindingV1;

pub(crate) fn validate_d2_target_snapshot(
    store: &runne_store::store::StoreTransaction,
    root_admission: &RootAdmissionGateway,
    workspace_id: runne_domain::id::WorkspaceId,
    binding: &ToolInvocationBindingV1,
    arguments: &[u8],
    receipt: &crate::safe_tool_helper::ReceiptV1,
) -> Result<(), ()> {
    use crate::application::exec_taskrun_worker::local::run::tool_executor as executor;

    if receipt.status != "success"
        || receipt.version
            != if binding.environment_id == crate::safe_tool_helper::coding_arguments::ENVIRONMENT {
                2
            } else {
                1
            }
        || receipt.path != binding.target_name
        || receipt.root.device == 0
        || receipt.root.inode == 0
        || receipt.truncated
    {
        return Err(());
    }
    let helper_digest = if binding.tool_name == "workspace.command.run" {
        Some(
            store
                .local_permission_preparation()
                .map_err(|_| ())?
                .tool_helper_executable_digest()
                .map_err(|_| ())?,
        )
    } else {
        None
    };
    root_admission
        .admit_coding_tool_target(workspace_id, &binding.tool_name, &binding.target_name)
        .map_err(|_| ())?;
    root_admission
        .with_local_command_root(
            workspace_id,
            |root, workspace_version, _, revision, identity, admission| {
                if revision != binding.root_revision
                    || identity != *binding.root_identity.as_bytes()
                {
                    return Err(runne_platform_desktop::RootHandleBrokerError::Rejected);
                }
                let files = root.open_linux_command_workspace(std::path::Path::new("."))?;
                let (device, inode) = executor::descriptor_identity(files.workspace())
                    .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?;
                if receipt.root.device != device || receipt.root.inode != inode {
                    return Err(runne_platform_desktop::RootHandleBrokerError::Rejected);
                }
                let coding = binding.environment_id
                    == crate::safe_tool_helper::coding_arguments::ENVIRONMENT;
                let directory = matches!(
                    binding.tool_name.as_str(),
                    "workspace.files.list" | "workspace.files.search" | "workspace.command.run"
                );
                let current = if coding {
                    crate::safe_tool_helper::coding_fs::snapshot(
                        files.workspace(),
                        &binding.target_name,
                        directory,
                    )
                    .map_err(|_| ())
                } else {
                    executor::capture_existing_target_snapshot(&files, &binding.target_name)
                }
                .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
                if (!directory && current != receipt.target)
                    || (directory
                        && (current.device, current.inode)
                            != (receipt.target.device, receipt.target.inode))
                {
                    return Err(runne_platform_desktop::RootHandleBrokerError::Rejected);
                }
                if binding.tool_name == "workspace.file.read" {
                    let digest = {
                        use sha2::{Digest, Sha256};
                        runne_domain::id::IntegrityDigest::from_bytes(
                            Sha256::digest(
                                serde_json::to_vec(&current).expect("version serializes"),
                            )
                            .into(),
                        )
                    };
                    if Some(digest) != binding.target_precondition {
                        return Err(runne_platform_desktop::RootHandleBrokerError::Rejected);
                    }
                } else if !coding
                    && (binding.tool_name != "workspace.file.create_new"
                        || binding.target_precondition.is_some())
                {
                    return Err(runne_platform_desktop::RootHandleBrokerError::Rejected);
                }
                let approved = super::approval_digest(
                    binding.key.taskrun_id,
                    binding.key.attempt_id,
                    binding.key.cycle_id,
                    binding.key.proposal_index,
                    binding.expected_taskrun_version,
                    &binding.call_id,
                    &binding.tool_name,
                    &binding.tool_revision,
                    &binding.environment_id,
                    &binding.approval_principal_id,
                    binding.schema_digest.as_bytes(),
                    arguments,
                    binding.target_precondition.as_ref().map(|v| v.as_bytes()),
                    binding.root_identity.as_bytes(),
                    revision,
                    workspace_version,
                    admission.token.instance_epoch,
                    admission.token.revision,
                    binding.approval_expires_at,
                    helper_digest.as_ref().map(|digest| digest.as_bytes()),
                );
                if approved != *binding.approval_digest.as_bytes() {
                    return Err(runne_platform_desktop::RootHandleBrokerError::Rejected);
                }
                Ok(())
            },
        )
        .map_err(|_| ())
}

#[derive(Clone)]
pub(crate) struct D2TargetFence {
    store: runne_store::store::StoreTransaction,
    workspace_id: runne_domain::id::WorkspaceId,
    root_admission: RootAdmissionGateway,
    snapshots: Vec<(
        ToolInvocationBindingV1,
        zeroize::Zeroizing<Vec<u8>>,
        crate::safe_tool_helper::ReceiptV1,
    )>,
}

impl D2TargetFence {
    pub(crate) fn validate(&self) -> Result<(), ()> {
        self.snapshots
            .iter()
            .try_for_each(|(binding, arguments, receipt)| {
                validate_d2_target_snapshot(
                    &self.store,
                    &self.root_admission,
                    self.workspace_id,
                    binding,
                    arguments,
                    receipt,
                )
            })
    }
}

impl super::super::DaemonAutomaticTaskRuns {
    pub(crate) fn validate_d2_current_targets(
        &self,
        workspace_id: runne_domain::id::WorkspaceId,
        taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<(), ()> {
        let count = self
            .store
            .load_taskrun_tool_invocations_for_taskrun(taskrun_id)
            .map_err(|_| ())?
            .len();
        if count == 0
            && self
                .provider
                .as_ref()
                .is_some_and(|p| p.coding_agent_tools_enabled())
        {
            return Ok(());
        }
        self.validate_d2_current_target_prefix(workspace_id, taskrun_id, count)
    }

    pub(crate) fn validate_d2_current_target_prefix(
        &self,
        workspace_id: runne_domain::id::WorkspaceId,
        taskrun_id: runne_domain::id::TaskRunId,
        expected_count: usize,
    ) -> Result<(), ()> {
        self.d2_current_target_fence(workspace_id, taskrun_id, expected_count)?
            .validate()
    }

    pub(crate) fn d2_current_target_fence(
        &self,
        workspace_id: runne_domain::id::WorkspaceId,
        taskrun_id: runne_domain::id::TaskRunId,
        expected_count: usize,
    ) -> Result<D2TargetFence, ()> {
        if !(1..=32).contains(&expected_count) {
            return Err(());
        }
        let provider = self.provider.as_ref().ok_or(())?;
        let records = self
            .store
            .load_taskrun_tool_invocations_for_taskrun(taskrun_id)
            .map_err(|_| ())?;
        if records.len() != expected_count {
            return Err(());
        }
        let mut snapshots = Vec::with_capacity(records.len());
        let mut latest = std::collections::BTreeMap::new();
        let mut last_command = None;
        for record in &records {
            if record.binding.environment_id
                == crate::safe_tool_helper::coding_arguments::ENVIRONMENT
            {
                latest.insert(
                    record.binding.target_name.clone(),
                    record.binding.key.proposal_index,
                );
                if record.binding.tool_name == "workspace.command.run" {
                    last_command = Some(record.binding.key.proposal_index);
                }
            }
        }
        for record in records {
            if record.binding.environment_id
                == crate::safe_tool_helper::coding_arguments::ENVIRONMENT
                && (latest
                    .get(&record.binding.target_name)
                    .is_some_and(|index| *index > record.binding.key.proposal_index)
                    || last_command.is_some_and(|index| index > record.binding.key.proposal_index))
            {
                continue;
            }

            let binding = &record.binding;
            let result = record.receipt.result.as_ref().ok_or(())?;
            let receipt = provider
                .open_d2_tool_receipt(
                    result.receipt_payload.key,
                    binding.key.taskrun_id,
                    binding.key.attempt_id,
                    binding.key.cycle_id,
                    binding.key.proposal_index,
                    binding.semantic_digest,
                    &result.receipt_payload.payload,
                )
                .map_err(|_| ())?;
            let receipt: crate::safe_tool_helper::ReceiptV1 =
                serde_json::from_slice(&receipt).map_err(|_| ())?;
            let arguments = provider
                .open_d2_tool_arguments(
                    record.arguments_payload.key,
                    binding.key.taskrun_id,
                    binding.key.attempt_id,
                    binding.key.cycle_id,
                    binding.key.proposal_index,
                    binding.semantic_digest,
                    &record.arguments_payload.payload,
                )
                .map_err(|_| ())?;
            snapshots.push((binding.clone(), arguments, receipt));
        }
        Ok(D2TargetFence {
            store: self.store.clone(),
            workspace_id,
            root_admission: self.root_admission.clone(),
            snapshots,
        })
    }
}
