use crate::canonical_provider::DaemonCanonicalProviderService;
use base64::Engine as _;
use runne_api::{ApiPrincipalId, TaskRunHostError, TaskRunToolActivityV1, ToolActivityEntryV1};
use runne_application::ports::{EventStore, ProjectWorkspaceRepository};
use runne_domain::{id::TaskRunId, task_run::TaskRun};
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};
use sha2::{Digest, Sha256};

pub(super) fn read(
    store: &StoreTransaction,
    provider: &DaemonCanonicalProviderService,
    principal: &ApiPrincipalId,
    taskrun_id: TaskRunId,
) -> Result<TaskRunToolActivityV1, TaskRunHostError> {
    let fail = |_| TaskRunHostError::Unavailable;
    let stream = store.load_task_run(taskrun_id).map_err(fail)?;
    let task = TaskRun::replay(&stream.events).map_err(|_| TaskRunHostError::Unavailable)?;
    let workspace_id = *task.workspace_id().ok_or(TaskRunHostError::NotFound)?;
    ProjectWorkspaceStore::from_store(store.clone())
        .get_workspace(principal.as_str(), workspace_id)
        .map_err(|_| TaskRunHostError::NotFound)?;
    let records = store
        .load_taskrun_tool_invocations_for_taskrun(taskrun_id)
        .map_err(|_| TaskRunHostError::Unavailable)?;
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let binding = &record.binding;
        let key = binding.key;
        if key.taskrun_id != taskrun_id || binding.principal_id != principal.as_str() {
            return Err(TaskRunHostError::NotFound);
        }
        let mut entry = ToolActivityEntryV1 {
            invocation_id: format!("{}:{}:{}", key.attempt_id, key.cycle_id, key.proposal_index),
            tool_name: binding.tool_name.clone(),
            target: binding.target_name.clone(),
            state: format!("{:?}", record.receipt.state).to_ascii_lowercase(),
            result_text: None,
            truncated: false,
        };
        // Scan metadata as well as decoded content; ciphertext is never returned.
        let metadata = format!("{}\n{}", entry.tool_name, entry.target);
        if !provider
            .tool_activity_content_allowed(metadata.as_bytes())
            .map_err(|_| TaskRunHostError::Unavailable)?
        {
            entry.target = "[withheld]".into();
            entry.tool_name = "[withheld]".into();
        }
        if let Some(result) = record.receipt.result {
            let plaintext = provider
                .open_d2_tool_receipt(
                    result.receipt_payload.key,
                    key.taskrun_id,
                    key.attempt_id,
                    key.cycle_id,
                    key.proposal_index,
                    binding.semantic_digest,
                    &result.receipt_payload.payload,
                )
                .map_err(|_| TaskRunHostError::Unavailable)?;
            let receipt: crate::safe_tool_helper::ReceiptV1 =
                serde_json::from_slice(&plaintext).map_err(|_| TaskRunHostError::Unavailable)?;
            if receipt.binding.taskrun_id != key.taskrun_id.to_string()
                || receipt.binding.attempt_id != key.attempt_id.to_string()
                || receipt.binding.cycle_id != key.cycle_id.to_string()
                || receipt.binding.proposal_index != key.proposal_index
                || receipt.binding.invocation_digest
                    != hex::encode(binding.semantic_digest.as_bytes())
            {
                return Err(TaskRunHostError::Unavailable);
            }
            let content = base64::engine::general_purpose::STANDARD
                .decode(&receipt.bytes_base64)
                .map_err(|_| TaskRunHostError::Unavailable)?;
            if content.len() > 8192
                || content.len() as u64 != result.actual_length
                || Sha256::digest(&content).as_slice() != result.digest.as_bytes()
            {
                return Err(TaskRunHostError::Unavailable);
            }
            entry.truncated = result.truncated || receipt.truncated;
            let (display, display_truncated) = display_content(&binding.tool_name, &content)?;
            entry.truncated |= display_truncated;
            entry.result_text = Some(
                if provider
                    .tool_activity_content_allowed(&content)
                    .map_err(|_| TaskRunHostError::Unavailable)?
                    && provider
                        .tool_activity_content_allowed(display.as_bytes())
                        .map_err(|_| TaskRunHostError::Unavailable)?
                {
                    let (text, truncated) = bounded_text(display.as_bytes());
                    entry.truncated |= truncated;
                    text
                } else {
                    "[withheld by content policy]".into()
                },
            );
        }
        entries.push(entry);
    }
    Ok(TaskRunToolActivityV1 {
        task_run_id: taskrun_id.to_string(),
        workspace_id: workspace_id.to_string(),
        entries,
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandOutput {
    exit_code: Option<i32>,
    timed_out: bool,
    output_truncated: bool,
    stdout_base64: String,
    stderr_base64: String,
}

fn display_content(tool: &str, bytes: &[u8]) -> Result<(String, bool), TaskRunHostError> {
    if tool != "workspace.command.run" {
        return Ok((String::from_utf8_lossy(bytes).into_owned(), false));
    }
    let output: CommandOutput =
        serde_json::from_slice(bytes).map_err(|_| TaskRunHostError::Unavailable)?;
    let decode = |encoded: &str| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| TaskRunHostError::Unavailable)?;
        if bytes.len() > 2048 {
            return Err(TaskRunHostError::Unavailable);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    };
    let display = format!(
        "exit: {:?}; timed out: {}\nstdout:\n{}\nstderr:\n{}",
        output.exit_code,
        output.timed_out,
        decode(&output.stdout_base64)?,
        decode(&output.stderr_base64)?
    );
    Ok((display, output.output_truncated))
}

// Lossy UTF-8 replacement may grow bytes; the public bound applies after conversion.
fn bounded_text(content: &[u8]) -> (String, bool) {
    let mut value = String::from_utf8_lossy(content).into_owned();
    let truncated = value.len() > 8192;
    if truncated {
        let mut end = 8192;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    (value, truncated)
}

#[cfg(test)]
mod tests {
    use super::{bounded_text, display_content};

    #[test]
    fn binary_command_output_remains_bounded_after_utf8_replacement() {
        let (text, truncated) = bounded_text(&[0xff; 8192]);
        assert!(truncated);
        assert!(text.len() <= 8192);
        assert!(!text.is_empty());
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }

    #[test]
    fn command_receipt_keeps_exit_stdout_and_stderr() {
        let original = br#"{"exit_code":17,"timed_out":false,"output_truncated":false,"stdout_base64":"b25l","stderr_base64":"dHdv"}"#;
        let (text, truncated) = display_content("workspace.command.run", original).unwrap();
        assert!(!truncated);
        assert!(text.contains("17") && text.contains("one") && text.contains("two"));
        assert!(!text.contains("b25l"));
        assert!(display_content("workspace.command.run", b"{}").is_err());
    }
}
