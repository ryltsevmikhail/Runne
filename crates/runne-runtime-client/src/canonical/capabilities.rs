/// Exact external/deterministic runtime capabilities. Ordering is canonical.
pub const REQUIRED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.submit.v1",
    "task_run.get.v1",
    "task_run.cancel.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "approval.control.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.rename.v1",
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
    "task_run.submit.v1",
    "task_run.get.v1",
    "task_run.cancel.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "approval.control.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.rename.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
    "workspace.bind_root.v3",
    "workspace.files.read.v1",
    "workspace.changes.read.v1",
    "workspace.editor.open.v1",
];

/// Exact protected profile shape that Task 15 may select after native release
/// qualification. Defining it does not authorize a profile to use it.
pub const ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.submit.v1",
    "task_run.get.v1",
    "task_run.cancel.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "approval.control.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.rename.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
    "workspace.bind_root.v3",
    "workspace.files.read.v1",
    "workspace.changes.read.v1",
    "workspace.editor.open.v1",
    PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2,
];

pub fn is_supported_capability_profile(values: &[String]) -> bool {
    [
        REQUIRED_RUNTIME_CAPABILITIES,
        PROTECTED_RUNTIME_CAPABILITIES,
        ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES,
    ]
    .iter()
    .any(|expected| {
        values
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

pub fn is_enrollment_qualified_capability_profile(values: &[String]) -> bool {
    values
        .iter()
        .map(String::as_str)
        .eq(ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES.iter().copied())
}

/// Verifies every protected-bundled profile field used by the native root
/// authority boundary. External clients never satisfy this predicate.
#[must_use]
pub fn protected_profile_matches(client: &AuthenticatedRuntimeClient) -> bool {
    let session = client.session_info();
    let result = client.transport_kind() == RuntimeTransportKind::ProtectedBundled
        && session.profile_id == crate::EXPECTED_BUNDLE_ID
        && session.schema_hash == crate::GOLDEN_BUNDLE_HASH
        && (session
            .capabilities
            .iter()
            .map(String::as_str)
            .eq(PROTECTED_RUNTIME_CAPABILITIES.iter().copied())
            || is_enrollment_qualified_capability_profile(&session.capabilities))
        && capability_digest_hex(&session.capabilities)
            .is_some_and(|digest| digest == session.capability_digest)
        && nonempty_identity(session);
    eprintln!(
        "[bindcheck] kind={:} profile={:} schema={:} caps={:} digest={:} identity={:} epoch={}",
        client.transport_kind() == RuntimeTransportKind::ProtectedBundled,
        session.profile_id == crate::EXPECTED_BUNDLE_ID,
        session.schema_hash == crate::GOLDEN_BUNDLE_HASH,
        session.capabilities.iter().map(String::as_str).eq(PROTECTED_RUNTIME_CAPABILITIES.iter().copied()),
        capability_digest_hex(&session.capabilities).is_some_and(|digest| digest == session.capability_digest),
        nonempty_identity(session),
        session.authorization_epoch,
    );
    result
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
}

#[cfg(test)]
mod capabilities_tests {
    use super::*;

    #[test]
    fn v1_credential_control_is_not_advertised_by_any_supported_profile() {
        for profile in [
            REQUIRED_RUNTIME_CAPABILITIES,
            PROTECTED_RUNTIME_CAPABILITIES,
        ] {
            assert!(
                !profile.contains(&"provider.credential-control.v1"),
                "V1 credential control must remain a compatibility artifact only"
            );
        }
    }

    #[test]
    fn enrollment_profile_is_exact_and_supported() {
        for profile in [REQUIRED_RUNTIME_CAPABILITIES, PROTECTED_RUNTIME_CAPABILITIES] {
            assert!(!profile.iter().any(|value| value.starts_with("provider.credential-")));
        }
        assert_eq!(ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES.iter().filter(|value| **value == PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2).count(), 1);
        assert!(!ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES.contains(&"provider.credential-control.v1"));
        let qualified = ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>();
        assert!(is_enrollment_qualified_capability_profile(&qualified));
        assert!(is_supported_capability_profile(&qualified));
        let mut mixed = qualified.clone(); mixed.swap(0, 1);
        assert!(!is_enrollment_qualified_capability_profile(&mixed));
        mixed = qualified; mixed.push("compile-only-qualification".to_owned());
        assert!(!is_enrollment_qualified_capability_profile(&mixed));
    }

    #[test]
    fn protected_profile_match_accepts_only_exact_qualified_capabilities() {
        let qualified = ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        assert!(protected_profile_matches(&protected_test_client(qualified)));

        for capabilities in [
            vec!["arbitrary.capability.v1".to_owned()],
            {
                let mut values = ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>();
                values.push("arbitrary.capability.v1".to_owned());
                values
            },
        ] {
            assert!(!protected_profile_matches(&protected_test_client(capabilities)));
        }
    }

    fn protected_test_client(capabilities: Vec<String>) -> AuthenticatedRuntimeClient {
        let capability_digest = capability_digest_hex(&capabilities).expect("bounded test capability");
        crate::mock_protected_authenticated_runtime_client(
            "http://127.0.0.1:43123",
            crate::RuntimeSessionInfo {
                profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
                schema_hash: crate::GOLDEN_BUNDLE_HASH.to_owned(),
                runtime_version: "test".to_owned(),
                capabilities,
                authority_id: "authority".to_owned(),
                principal_id: "principal".to_owned(),
                event_log_lineage_id: "lineage".to_owned(),
                daemon_instance_id: "daemon".to_owned(),
                launch_generation: 1,
                session_id: "session".to_owned(),
                authorization_epoch: 1,
                sensitivity_ceiling: "sensitive".to_owned(),
                certificate_sha256: "certificate".to_owned(),
                capability_digest,
            },
        )
        .expect("protected test client")
    }
}
