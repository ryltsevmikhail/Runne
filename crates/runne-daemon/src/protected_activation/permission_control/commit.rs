use runne_api::{
    LaunchAuthorityError, PermissionControlModeConsentV1, PermissionControlResultV1,
    ProtectedActivationKeys,
};

include!("commit_support.rs");

#[cfg(all(unix, feature = "desktop-protected"))]
impl PermissionControlHost {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_mode(
        &self,
        principal: &ApiPrincipalId,
        workspace: runne_domain::id::WorkspaceId,
        context: &PermissionControlContextV1,
        consent: &PermissionControlModeConsentV1,
        keys: &ProtectedActivationKeys,
        now: u64,
        root: &crate::application::root_handle_admission::RootAdmissionGateway,
    ) -> Result<PermissionControlResultV1, LaunchAuthorityError> {
        self.with_current_launch(principal, |launch| {
            validate_owner_context(
                self,
                launch,
                principal,
                context,
                keys.permission_control_native_authenticator()
                    .native_key_epoch(),
            )
            .map_err(|_| runne_api::PermissionModeHostErrorV1::NativeAuthorityUnavailable)?;
            let command_id = runne_domain::id::CommandId::from_bytes(context.command_id);
            let scope = permission_scope(self, principal, workspace);
            let status = self
                .store()
                .load_permission_mode_confirmation_status_v2(&scope, principal, command_id)
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?
                .ok_or(runne_api::PermissionModeHostErrorV1::NotFound)?;
            let runne_store::store::PermissionModeCeremonyStatusV2::Pending(issued) = status else {
                return crate::protected_activation::permission_mode_status_result(
                    status,
                    command_id,
                    context.public_request_digest,
                )
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable);
            };
            let pending = self
                .store()
                .discover_permission_mode_native_pending_command_v2(principal, launch, command_id)
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?
                .ok_or(runne_api::PermissionModeHostErrorV1::NativeAuthorityUnavailable)?;
            let mut canonical = pending
                .context
                .control_context()
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?;
            canonical.predecessor_transcript_digest = context.predecessor_transcript_digest;
            let binding = issued.binding();
            if pending.workspace_id != workspace.to_string()
                || canonical != *context
                || consent.challenge_id != *issued.challenge_id()
                || consent.public_request_digest != *binding.public_request_digest.as_bytes()
                || consent.issued_challenge_binding_digest
                    != *binding.challenge_binding_digest.as_bytes()
                || consent.native_warning_version != binding.native_warning_version
                || consent.confirmed_binding_digest != *binding.digest().as_bytes()
                || permission_mode(consent.requested_mode) != binding.requested_mode
            {
                return Err(runne_api::PermissionModeHostErrorV1::NativeAuthorityUnavailable);
            }
            let now = i64::try_from(now)
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?;
            let verifier = ConsentVerifier {
                authenticator: keys.permission_control_native_authenticator(),
                context,
                consent,
            };
            let verified = runne_application::permission_modes::verify_native_mode_confirmation_v2(
                binding,
                &consent.warning_attestation,
                now,
                &verifier,
            )
            .map_err(|_| runne_api::PermissionModeHostErrorV1::NativeAuthorityUnavailable)?;
            let workspace_row = self
                .workspaces()
                .get_workspace(principal.as_str(), workspace)
                .map_err(|_| runne_api::PermissionModeHostErrorV1::NotFound)?;
            if !workspace_row.open_state() {
                return Err(runne_api::PermissionModeHostErrorV1::NotFound);
            }
            let project = runne_application::project_trust::ProjectTrustProjectId::from_bytes(
                *workspace_row.project_id().as_bytes(),
            );
            let trust = self
                .trust()
                .ok_or(runne_api::PermissionModeHostErrorV1::Unavailable)?;
            let full = binding.requested_mode
                == runne_application::permission_modes::PermissionMode::FullAccess;
            let mut command = runne_application::permission_modes::SetPermissionModeCommand {
                command_id,
                scope: binding.scope.clone(),
                expected_authorization_revision: binding.expected_authorization_revision,
                requested_mode: binding.requested_mode,
                preset_version: binding.preset_version,
                intent_digest: runne_domain::id::IntegrityDigest::from_bytes([0; 32]),
                idempotency_key: binding.idempotency_key.clone(),
                expires_at_unix_ms: binding.expires_at_unix_ms,
                managed_policy_version: binding.managed_policy_version,
                managed_policy_digest: binding.managed_policy_digest,
                challenge_binding_digest: full.then_some(binding.challenge_binding_digest),
                challenge_expires_at_unix_ms: full.then_some(binding.challenge_expires_at_unix_ms),
                verified_native_challenge: None,
            };
            command.intent_digest = command.computed_intent_digest();
            if full {
                let legacy_binding =
                    runne_application::permission_modes::FullAccessChallengeBinding {
                        command_id,
                        idempotency_key: command.idempotency_key.clone(),
                        scope: command.scope.clone(),
                        expected_authorization_revision: command.expected_authorization_revision,
                        requested_mode: command.requested_mode,
                        preset_version: command.preset_version,
                        managed_policy_version: command.managed_policy_version,
                        managed_policy_digest: command.managed_policy_digest,
                        intent_digest: command.intent_digest,
                        challenge_binding_digest: binding.challenge_binding_digest,
                        expires_at_unix_ms: command.expires_at_unix_ms,
                        challenge_expires_at_unix_ms: binding.challenge_expires_at_unix_ms,
                    };
                command.verified_native_challenge = Some(
                    runne_application::permission_modes::verify_full_access_challenge(
                        &legacy_binding,
                        &consent.warning_attestation,
                        now,
                        &verifier,
                    )
                    .map_err(|_| {
                        runne_api::PermissionModeHostErrorV1::NativeAuthorityUnavailable
                    })?,
                );
            }
            let next_revision = command
                .expected_authorization_revision
                .checked_add(1)
                .ok_or(runne_api::PermissionModeHostErrorV1::StaleRevision)?;
            let selection = runne_application::permission_modes::ModeSelection {
                scope: command.scope.clone(),
                selected_mode: command.requested_mode,
                preset_version: command.preset_version,
                authorization_revision: next_revision,
                expires_at_unix_ms: command.expires_at_unix_ms,
            };
            let projection = crate::application::permission_projection::current_projection(
                crate::application::permission_projection::ProjectionMetadata {
                    selection: selection.clone(),
                    managed_policy_version: command.managed_policy_version,
                },
                || {
                    crate::application::permission_projection::observe_current_target(
                        self.store(),
                        self.workspaces(),
                        root,
                        principal,
                        workspace,
                        launch,
                        &crate::application::permission_projection::ProjectionTarget::Candidate {
                            selection,
                            expected_revision: command.expected_authorization_revision,
                            managed_policy_version: command.managed_policy_version,
                            managed_policy_digest: command.managed_policy_digest,
                        },
                    )
                },
            );
            let history = projection.history_snapshot();
            let lease = trust
                .acquire_effect_lease(
                    project,
                    runne_application::project_trust::SourceAdmissionRequest {
                        channel: runne_application::project_trust::SourceChannel::FilesList,
                        path: None,
                        observed_token: None,
                        permission_mode: runne_application::project_trust::PermissionMode::Ask,
                    },
                )
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?;
            let authority = runne_store::store::PermissionModeAuthorityContext::new(
                principal,
                project,
                lease.as_ref(),
                Some(launch),
            );
            let committed = self
                .store()
                .commit_confirmed_permission_mode_v2(command, verified, &authority, history)
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?;
            let readback = self
                .store()
                .load_permission_mode_confirmation_status_v2(&scope, principal, command_id)
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?
                .ok_or(runne_api::PermissionModeHostErrorV1::Unavailable)?;
            if readback != runne_store::store::PermissionModeCeremonyStatusV2::Committed(committed)
            {
                return Err(runne_api::PermissionModeHostErrorV1::Unavailable);
            }
            crate::protected_activation::permission_mode_status_result(
                readback,
                command_id,
                context.public_request_digest,
            )
            .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)
        })
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    }

    pub(crate) fn cancel_mode(
        &self,
        principal: &ApiPrincipalId,
        workspace: runne_domain::id::WorkspaceId,
        context: &PermissionControlContextV1,
    ) -> Result<PermissionControlResultV1, LaunchAuthorityError> {
        self.with_current_launch(principal, |launch| {
            let command_id = runne_domain::id::CommandId::from_bytes(context.command_id);
            validate_owner_context(self, launch, principal, context, launch.key_epoch())
                .map_err(|_| runne_api::PermissionModeHostErrorV1::NativeAuthorityUnavailable)?;
            let scope = permission_scope(self, principal, workspace);
            let status = self
                .store()
                .load_permission_mode_confirmation_status_v2(&scope, principal, command_id)
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?
                .ok_or(runne_api::PermissionModeHostErrorV1::NotFound)?;
            if matches!(
                &status,
                runne_store::store::PermissionModeCeremonyStatusV2::Pending(_)
            ) {
                let pending = self
                    .store()
                    .discover_permission_mode_native_pending_command_v2(
                        principal, launch, command_id,
                    )
                    .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?
                    .ok_or(runne_api::PermissionModeHostErrorV1::NativeAuthorityUnavailable)?;
                let mut canonical = pending
                    .context
                    .control_context()
                    .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?;
                canonical.predecessor_transcript_digest = context.predecessor_transcript_digest;
                if pending.workspace_id != workspace.to_string() || canonical != *context {
                    return Err(runne_api::PermissionModeHostErrorV1::NativeAuthorityUnavailable);
                }
                self.store()
                    .cancel_permission_mode_confirmation_v2(&scope, principal, command_id)
                    .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?;
            }
            let readback = self
                .store()
                .load_permission_mode_confirmation_status_v2(&scope, principal, command_id)
                .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)?
                .ok_or(runne_api::PermissionModeHostErrorV1::Unavailable)?;
            crate::protected_activation::permission_mode_status_result(
                readback,
                command_id,
                context.public_request_digest,
            )
            .map_err(|_| runne_api::PermissionModeHostErrorV1::Unavailable)
        })
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    }
}
