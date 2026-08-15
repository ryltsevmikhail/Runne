/// Exact external/deterministic runtime capabilities. Ordering is canonical.
pub const REQUIRED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.get.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
];

/// Exact protected-desktop extension, enabled only with native root authority.
pub const PROTECTED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.get.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
    "workspace.bind_root.v3",
];

pub fn is_supported_capability_profile(values: &[String]) -> bool {
    [
        REQUIRED_RUNTIME_CAPABILITIES,
        PROTECTED_RUNTIME_CAPABILITIES,
    ]
    .iter()
    .any(|expected| {
        values
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

/// Verifies every protected-bundled profile field used by the native root
/// authority boundary. External clients never satisfy this predicate.
#[must_use]
pub fn protected_profile_matches(client: &AuthenticatedRuntimeClient) -> bool {
    let session = client.session_info();
    client.transport_kind() == RuntimeTransportKind::ProtectedBundled
        && session.profile_id == crate::EXPECTED_BUNDLE_ID
        && session.schema_hash == crate::GOLDEN_BUNDLE_HASH
        && session
            .capabilities
            .iter()
            .map(String::as_str)
            .eq(PROTECTED_RUNTIME_CAPABILITIES.iter().copied())
        && capability_digest_hex(&session.capabilities)
            .is_some_and(|digest| digest == session.capability_digest)
        && nonempty_identity(session)
}

fn capability_digest_hex(capabilities: &[String]) -> Option<String> {
    use sha2::Digest;
    if capabilities
        .iter()
        .any(|value| value.len() > u32::MAX as usize)
    {
        return None;
    }
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(u32::try_from(capabilities.len()).ok()?.to_be_bytes());
    for value in capabilities {
        digest.update(u32::try_from(value.len()).ok()?.to_be_bytes());
        digest.update(value.as_bytes());
    }
    Some(hex::encode(digest.finalize()))
}

fn nonempty_identity(session: &RuntimeSessionInfo) -> bool {
    [
        &session.authority_id,
        &session.principal_id,
        &session.event_log_lineage_id,
        &session.daemon_instance_id,
        &session.session_id,
        &session.certificate_sha256,
    ]
    .into_iter()
    .all(|value| !value.is_empty())
        && session.launch_generation != 0
        && session.authorization_epoch != 0
}
