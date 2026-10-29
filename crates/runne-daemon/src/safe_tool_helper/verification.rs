use super::{IdentityV1, ReceiptV1, parse_output};
use runne_domain::id::IntegrityDigest;
use runne_store::store::taskrun_tool_invocation::ToolInvocationBindingV1;
use sha2::{Digest, Sha256};

/// Checks a decrypted helper receipt against its immutable invocation record.
pub(crate) fn verify_bound_receipt(
    binding: &ToolInvocationBindingV1,
    approved_arguments: &[u8],
    assignment_fence: u64,
    receipt_bytes: &[u8],
    result_digest: IntegrityDigest,
    actual_length: u64,
) -> Result<(ReceiptV1, Vec<u8>), ()> {
    let receipt = parse_output(receipt_bytes).map_err(|_| ())?;
    let content = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        receipt.bytes_base64.as_bytes(),
    )
    .map_err(|_| ())?;
    let env_digest = Sha256::digest(
        format!(
            "{}\0{}",
            binding.environment_id, binding.environment_revision
        )
        .as_bytes(),
    );
    let mut root = Vec::with_capacity(16);
    root.extend_from_slice(&receipt.root.device.to_be_bytes());
    root.extend_from_slice(&receipt.root.inode.to_be_bytes());
    let root_digest = Sha256::digest(&root);
    let coding = binding.environment_id == super::coding_arguments::ENVIRONMENT;
    let expected_operation = super::coding_arguments::operation(&binding.tool_name)?;
    let schema = if coding {
        runne_provider::ProviderToolDeclarationV1::coding_agent_current_platform()
    } else {
        vec![
            runne_provider::ProviderToolDeclarationV1::for_name(
                runne_provider::ProviderToolNameV1::WorkspaceFileRead,
            ),
            runne_provider::ProviderToolDeclarationV1::for_name(
                runne_provider::ProviderToolNameV1::WorkspaceFileCreateNew,
            ),
        ]
    };
    if binding.tool_revision != "1"
        || binding.environment_revision != "1"
        || (!coding && binding.environment_id != "linux-agent-tools-v1")
        || binding.schema_digest.as_bytes()
            != Sha256::digest(serde_json::to_vec(&schema).map_err(|_| ())?).as_slice()
    {
        return Err(());
    }
    let arguments_digest = Sha256::digest(approved_arguments);
    if arguments_digest.as_slice() != binding.arguments_digest.as_bytes() {
        return Err(());
    }
    let arguments: serde_json::Value =
        serde_json::from_slice(approved_arguments).map_err(|_| ())?;
    let object = arguments.as_object().ok_or(())?;
    let approved_content = if coding {
        let parsed = super::coding_arguments::parse(&binding.tool_name, &arguments)?;
        if parsed.path != binding.target_name {
            return Err(());
        }
        parsed.content
    } else {
        if object.get("path").and_then(serde_json::Value::as_str)
            != Some(binding.target_name.as_str())
        {
            return Err(());
        }
        match binding.tool_name.as_str() {
            "workspace.file.read" if object.len() == 1 => vec![],
            "workspace.file.create_new" if object.len() == 2 => base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                object["content_base64"].as_str().ok_or(())?,
            )
            .map_err(|_| ())?,
            _ => return Err(()),
        }
    };
    if matches!(
        binding.tool_name.as_str(),
        "workspace.file.create_new" | "workspace.file.replace"
    ) && approved_content != content
    {
        return Err(());
    }
    if receipt.status != "success"
        || receipt.version != if coding { 2 } else { 1 }
        || receipt.truncated
        || receipt.operation != expected_operation
        || receipt.path != binding.target_name
        || receipt.binding.taskrun_id != binding.key.taskrun_id.to_string()
        || receipt.binding.attempt_id != binding.key.attempt_id.to_string()
        || receipt.binding.cycle_id != binding.key.cycle_id.to_string()
        || receipt.binding.proposal_index != binding.key.proposal_index
        || receipt.binding.taskrun_version != binding.expected_taskrun_version
        || receipt.binding.assignment_fence != assignment_fence
        || receipt.binding.invocation_digest != hex::encode(binding.semantic_digest.as_bytes())
        || receipt.binding.approval_digest != hex::encode(binding.approval_digest.as_bytes())
        || receipt.binding.environment_digest != hex::encode(env_digest)
        || receipt.binding.expires_at_unix_ms != binding.approval_expires_at as u64
        || hex::encode(root_digest) != hex::encode(binding.root_identity.as_bytes())
        || receipt.byte_length as u64 != actual_length
        || content.len() as u64 != actual_length
        || receipt.sha256 != hex::encode(result_digest.as_bytes())
        || hex::encode(Sha256::digest(&content)) != receipt.sha256
    {
        return Err(());
    }
    if binding.tool_name == "workspace.file.read" {
        let target_digest = Sha256::digest(serde_json::to_vec(&receipt.target).map_err(|_| ())?);
        if binding
            .target_precondition
            .map(|digest| digest.as_bytes().to_vec())
            != Some(target_digest.to_vec())
        {
            return Err(());
        }
    } else if !coding && binding.target_precondition.is_some() {
        return Err(());
    }
    Ok((receipt, content))
}

#[allow(dead_code)]
fn _identity_type_check(_: &IdentityV1) {}
