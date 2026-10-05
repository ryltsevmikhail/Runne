pub(super) fn validate_binding(
    b: &ToolInvocationBindingV1,
) -> Result<(), ToolInvocationStoreError> {
    if b.expected_taskrun_version == 0
        || b.canonical_arguments.is_empty()
        || b.canonical_arguments.len() > MAX_TOOL_ARGUMENT_BYTES
        || b.sources.is_empty()
        || b.sources.len() > 32
        || b.call_id.is_empty()
        || b.call_id.len() > 256
        || b.tool_name.is_empty()
        || b.tool_name.len() > 128
        || b.tool_revision.is_empty()
        || b.tool_revision.len() > 128
        || b.environment_id.is_empty()
        || b.environment_revision.is_empty()
        || b.root_revision == 0
        || b.target_name.is_empty()
        || b.target_name.len() > 255
        || b.approval_action.is_empty()
        || b.approval_action.len() > 256
        || b.approval_resource.is_empty()
        || b.approval_resource.len() > 4096
        || b.target_name.contains('/')
        || b.target_name.contains('\\')
        || b.target_name == "."
        || b.target_name == ".."
        || b.approval_id == [0; 16]
        || b.principal_id.is_empty()
        || b.approval_principal_id.is_empty()
        || b.policy_revision == 0
        || b.approval_expires_at <= 0
        || b.round_index > MAX_CONTINUATIONS
    {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    if hash(&b.canonical_arguments) != b.arguments_digest {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let value: serde_json::Value = serde_json::from_slice(&b.canonical_arguments)
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if serde_json::to_vec(&value).map_err(|_| ToolInvocationStoreError::CorruptData)?
        != b.canonical_arguments
    {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    let mut sources = b.sources.clone();
    sources.sort_by_key(|s| (s.dispatch_attempt_id, s.sequence));
    if sources.windows(2).any(|p| {
        p[0].dispatch_attempt_id == p[1].dispatch_attempt_id && p[0].sequence == p[1].sequence
    }) || b.semantic_digest != semantic_digest(b)
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    Ok(())
}

pub(super) fn semantic_digest(b: &ToolInvocationBindingV1) -> IntegrityDigest {
    let mut h = Sha256::new();
    h.update(b"runne-taskrun-tool-invocation-v1\0");
    h.update(b.key.taskrun_id.as_bytes());
    h.update(b.key.attempt_id.as_bytes());
    h.update(b.key.cycle_id.as_bytes());
    h.update(b.key.proposal_index.to_be_bytes());
    h.update(b.expected_taskrun_version.to_be_bytes());
    put(&mut h, &b.call_id);
    put(&mut h, &b.tool_name);
    put(&mut h, &b.tool_revision);
    h.update(b.schema_digest.as_bytes());
    h.update(b.arguments_digest.as_bytes());
    h.update(b.canonical_arguments.as_slice());
    h.update(encode_sources(&b.sources));
    put(&mut h, &b.environment_id);
    put(&mut h, &b.environment_revision);
    h.update(b.root_identity.as_bytes());
    h.update(b.root_revision.to_be_bytes());
    put(&mut h, &b.target_name);
    h.update(b.target_precondition.map_or([0; 32], |v| *v.as_bytes()));
    h.update(b.approval_id);
    put(&mut h, &b.principal_id);
    put(&mut h, &b.approval_principal_id);
    put(&mut h, &b.approval_action);
    put(&mut h, &b.approval_resource);
    h.update(b.approval_digest.as_bytes());
    h.update(b.policy_revision.to_be_bytes());
    h.update(b.approval_expires_at.to_be_bytes());
    h.update(b.round_index.to_be_bytes());
    IntegrityDigest::from_bytes(h.finalize().into())
}

pub(super) fn effect_digest(b: &ToolInvocationBindingV1) -> IntegrityDigest {
    let mut h = Sha256::new();
    h.update(b"runne-taskrun-tool-effect-v1\0");
    h.update(b.key.taskrun_id.as_bytes());
    put(&mut h, &b.tool_name);
    put(&mut h, &b.tool_revision);
    h.update(b.schema_digest.as_bytes());
    h.update(b.arguments_digest.as_bytes());
    put(&mut h, &b.environment_id);
    put(&mut h, &b.environment_revision);
    h.update(b.root_identity.as_bytes());
    h.update(b.root_revision.to_be_bytes());
    put(&mut h, &b.target_name);
    h.update(b.target_precondition.map_or([0; 32], |v| *v.as_bytes()));
    IntegrityDigest::from_bytes(h.finalize().into())
}

fn put(h: &mut Sha256, value: &str) {
    h.update((value.len() as u32).to_be_bytes());
    h.update(value.as_bytes());
}
pub(super) fn hash(bytes: &[u8]) -> IntegrityDigest {
    IntegrityDigest::from_bytes(Sha256::digest(bytes).into())
}

pub(super) fn encode_sources(sources: &[ToolSourceRef]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(sources.len() * 98);
    for s in sources {
        bytes.extend_from_slice(&s.dispatch_attempt_id);
        bytes.extend_from_slice(&s.sequence.to_be_bytes());
        bytes.push(s.event_kind);
        bytes.push(u8::from(s.terminal));
        bytes.extend_from_slice(s.plaintext_digest.as_bytes());
        bytes.extend_from_slice(s.profile_digest.as_bytes());
        bytes.extend_from_slice(&s.runtime_generation.to_be_bytes());
    }
    bytes
}
