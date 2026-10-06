#[test]
fn approval_cannot_create_missing_rights_or_escape_bounded_held_roots() {
    let mut no_write = bounded_scope();
    no_write
        .filesystem
        .permissions
        .remove(&FilesystemPermission::Write);
    let mut write = input(
        PermissionMode::AskAlways,
        PermissionAction::FsWrite,
        safe_target(),
        no_write,
    );
    write.invocation.approved_binding = Some(write.invocation.candidate_binding.clone());
    assert_eq!(
        PermissionPolicyCompiler::compile(&write),
        PolicyDecision::Deny(DenyReason::OutsideAdmittedScope)
    );

    let mut no_fs = bounded_scope();
    no_fs.filesystem.posture = FilesystemPosture::None;
    no_fs.filesystem.permissions.clear();
    let mut read = input(
        PermissionMode::AskAlways,
        PermissionAction::FsRead,
        safe_target(),
        no_fs,
    );
    read.invocation.approved_binding = Some(read.invocation.candidate_binding.clone());
    assert_eq!(
        PermissionPolicyCompiler::compile(&read),
        PolicyDecision::Deny(DenyReason::OutsideAdmittedScope)
    );

    let mut bounded = input(
        PermissionMode::AskAlways,
        PermissionAction::FsRead,
        unheld_outside_target(),
        bounded_scope(),
    );
    bounded.invocation.approved_binding = Some(bounded.invocation.candidate_binding.clone());
    assert_eq!(
        PermissionPolicyCompiler::compile(&bounded),
        PolicyDecision::Deny(DenyReason::OutsideAdmittedScope)
    );
}

#[test]
fn admitted_bounded_root_outside_workspace_can_proceed_after_exact_approval() {
    let mut facts = outside_safe_target();
    facts.resolved_path =
        Some(FilesystemRoot::new(digest(11), vec!["archive".into(), "x.txt".into()]).unwrap());
    let mut request = input(
        PermissionMode::AskAlways,
        PermissionAction::FsRead,
        facts,
        bounded_scope(),
    );
    request.invocation.approved_binding = Some(request.invocation.candidate_binding.clone());
    assert!(matches!(
        PermissionPolicyCompiler::compile(&request),
        PolicyDecision::Allow { .. }
    ));
}

#[test]
fn exact_scope_equality_is_valid_and_native_handle_must_match() {
    let request = input(
        PermissionMode::RiskBased,
        PermissionAction::FsRead,
        safe_target(),
        bounded_scope(),
    );
    assert_eq!(request.effective_scope, request.invocation.composite_scope);
    assert!(matches!(
        PermissionPolicyCompiler::compile(&request),
        PolicyDecision::Allow { .. }
    ));

    let mut mismatched = request;
    mismatched.invocation.native_admission = None;
    assert_eq!(
        PermissionPolicyCompiler::compile(&mismatched),
        PolicyDecision::Deny(DenyReason::OutsideAdmittedScope)
    );
}

#[test]
fn not_ready_expired_and_unknown_process_composite_never_release() {
    let mut not_ready = full_access_input(
        PermissionMode::FullAccess,
        PermissionAction::ProcessStart,
        process_facts(),
    );
    not_ready.effective = EffectiveModeState::NotReady(NotReadyReason::NativeContainment);
    assert_eq!(
        PermissionPolicyCompiler::compile(&not_ready),
        PolicyDecision::Deny(DenyReason::EffectiveModeNotReady)
    );

    let mut expired = input(
        PermissionMode::RiskBased,
        PermissionAction::FsRead,
        safe_target(),
        bounded_scope(),
    );
    expired.selection.expires_at_unix_ms = Some(100);
    assert_eq!(
        PermissionPolicyCompiler::compile(&expired),
        PolicyDecision::Deny(DenyReason::Expired)
    );

    let mut no_native_process = full_access_input(
        PermissionMode::FullAccess,
        PermissionAction::ProcessStart,
        process_facts(),
    );
    no_native_process.invocation.native_admission = None;
    assert_eq!(
        PermissionPolicyCompiler::compile(&no_native_process),
        PolicyDecision::Deny(DenyReason::OutsideAdmittedScope)
    );
}

#[test]
fn approval_binding_is_exact_and_expires_without_binding_transport_epoch_or_message() {
    let binding = candidate(PermissionAction::FsWrite, &bounded_scope());
    assert!(binding.is_compatible_with(&binding.clone(), 100));
    let mut changed = binding.clone();
    changed.environment_digest = digest(77);
    assert!(!binding.is_compatible_with(&changed, 100));
    changed = binding.clone();
    changed.target_version += 1;
    assert!(!binding.is_compatible_with(&changed, 100));
    assert!(!binding.is_compatible_with(&binding, binding.expires_at_unix_ms));
}

#[test]
fn composite_scope_digest_binds_posture_and_child_attenuation_identity() {
    let parent = bounded_scope();
    let mut changed = parent.clone();
    changed.filesystem.posture = FilesystemPosture::BroadSameUser;
    changed.network = NetworkScope::BroadSameUser;
    changed.containment = ContainmentStrategy::SameUserCompositeV1;
    assert_ne!(parent.digest().unwrap(), changed.digest().unwrap());

    let mut child = parent.clone();
    assert!(child.is_attenuated_from(&parent));
    child.permission_scope.workspace_id = workspace(2);
    assert!(!child.is_attenuated_from(&parent));
    child = parent.clone();
    child.protected_control_plane_policy_digest = digest(88);
    assert!(!child.is_attenuated_from(&parent));
}

#[test]
fn invalid_composite_roots_and_missing_protected_digest_reject_before_digest() {
    let mut scope = bounded_scope();
    scope.protected_control_plane_policy_digest = digest(0);
    assert_eq!(
        scope.digest(),
        Err(ScopeError::MissingProtectedControlPlanePolicy)
    );
    scope = bounded_scope();
    scope.filesystem.posture = FilesystemPosture::BoundedRoots(BTreeSet::from([FilesystemRoot {
        root_identity: digest(0),
        components: vec![],
    }]));
    assert_eq!(scope.digest(), Err(ScopeError::InvalidRootIdentity));
}

#[test]
fn managed_policy_digest_binds_the_current_project_trust_record() {
    use crate::project_trust::{ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus};

    let project = ProjectTrustProjectId::from_bytes([1; 16]);
    let record = ProjectTrustRecord {
        status: ProjectTrustStatus::Managed,
        instance_epoch: 7,
        revision: 9,
        managed_deny_mask: 5,
    };
    let digest = managed_policy_semantics_digest(project, record);
    assert_eq!(digest, managed_policy_semantics_digest(project, record));
    assert_ne!(
        digest,
        managed_policy_semantics_digest(
            project,
            ProjectTrustRecord {
                revision: 10,
                ..record
            }
        )
    );
    assert_ne!(
        digest,
        managed_policy_semantics_digest(
            project,
            ProjectTrustRecord {
                managed_deny_mask: 6,
                ..record
            }
        )
    );
}

#[test]
fn full_access_proof_is_command_bound_pending_and_finite_expiry() {
    struct FixtureVerifier;
    impl NativeChallengeVerifier for FixtureVerifier {
        fn verify(
            &self,
            binding: &FullAccessChallengeBinding,
            proof: &[u8],
        ) -> Result<IntegrityDigest, NativeChallengeError> {
            if proof == b"fixture-only" {
                Ok(binding.challenge_binding_digest)
            } else {
                Err(NativeChallengeError::Rejected)
            }
        }
    }

    let challenge_digest = digest(70);
    let command_id = CommandId::from_str("018f2e3a-7000-7000-8000-000000000004").unwrap();
    let idempotency_key = IdempotencyKey::new("mode-change-1").unwrap();
    let binding = FullAccessChallengeBinding {
        command_id,
        idempotency_key: idempotency_key.clone(),
        scope: permission_scope(),
        expected_authorization_revision: 3,
        requested_mode: PermissionMode::FullAccess,
        preset_version: PresetVersion::V1,
        managed_policy_version: 8,
        managed_policy_digest: digest(31),
        intent_digest: digest(40),
        challenge_binding_digest: challenge_digest,
        expires_at_unix_ms: Some(10_000),
        challenge_expires_at_unix_ms: 500,
    };
    let verified =
        verify_full_access_challenge(&binding, b"fixture-only", 499, &FixtureVerifier).unwrap();
    assert_eq!(verified.proof_identifier(), challenge_digest);
    assert!(matches!(
        verify_full_access_challenge(&binding, b"fixture-only", 500, &FixtureVerifier),
        Err(NativeChallengeError::Rejected)
    ));

    let mut command = SetPermissionModeCommand {
        command_id,
        scope: binding.scope.clone(),
        expected_authorization_revision: binding.expected_authorization_revision,
        requested_mode: PermissionMode::FullAccess,
        preset_version: PresetVersion::V1,
        intent_digest: digest(0),
        idempotency_key,
        expires_at_unix_ms: binding.expires_at_unix_ms,
        managed_policy_version: binding.managed_policy_version,
        managed_policy_digest: binding.managed_policy_digest,
        challenge_binding_digest: Some(challenge_digest),
        challenge_expires_at_unix_ms: Some(binding.challenge_expires_at_unix_ms),
        verified_native_challenge: None,
    };
    command.intent_digest = command.computed_intent_digest();
    let signing_binding = FullAccessChallengeBinding {
        intent_digest: command.intent_digest,
        ..binding
    };
    command.verified_native_challenge = Some(
        verify_full_access_challenge(&signing_binding, b"fixture-only", 499, &FixtureVerifier)
            .unwrap(),
    );
    assert!(validate_mode_change_command(&command).is_ok());
    command.command_id = CommandId::from_str("018f2e3a-7000-7000-8000-000000000005").unwrap();
    assert_eq!(
        validate_mode_change_command(&command),
        Err(PermissionModeError::ReauthenticationRequired)
    );
}
