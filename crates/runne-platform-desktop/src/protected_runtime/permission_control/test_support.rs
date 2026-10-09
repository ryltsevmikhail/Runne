const MOCK_PAM_FINGERPRINT: [u8; 32] = [0xa7; 32];

impl ProtectedBundledRuntimeSupervisor {
    /// Completes only the active mode exchange using explicit mock native evidence.
    ///
    /// This test-support method does not show GTK or perform PAM. Never use its
    /// result as evidence that the native warning or OS reauthentication ran.
    #[doc(hidden)]
    ///
    /// # Errors
    /// Returns an error when there is no valid active exchange or its completion fails.
    pub fn test_complete_permission_mode_with_mock_native_authority(
        &mut self,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        let (exchange, _) = self.current_permission_mode_exchange()?;
        let warning = crate::permission_reauth_linux::mock_native_permission_warning_confirmation(
            &exchange.challenge,
            &exchange.context,
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let os_reauthentication = if exchange.challenge.requested_mode
            == runne_api::PermissionModeSelectionV1::FullAccess
        {
            let now = std::time::Instant::now();
            let deadline = now
                .checked_add(std::time::Duration::from_secs(10))
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            Some(runne_linux_pam::FreshOsReauthentication::test_fixture(
                exchange.challenge.issued_challenge_binding_digest,
                rustix::process::geteuid().as_raw(),
                MOCK_PAM_FINGERPRINT,
                unix_millis()?,
                deadline,
                now,
            ))
        } else {
            None
        };
        self.complete_permission_mode_consent_with_consumer(
            warning,
            os_reauthentication,
            |token, challenge_digest| {
                token
                    .consume_verified(challenge_digest, MOCK_PAM_FINGERPRINT)
                    .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
            },
        )
    }
}

#[cfg(all(test, unix, feature = "protected-channel-integration"))]
mod v2_owner_tests {
    use super::*;

    fn v2_activation() -> (
        ProtectedProcessActivation,
        runne_api::ProtectedActivationKeys,
        runne_api::ProtectedOwnedLaunchV2,
    ) {
        let profile = expected_profile().unwrap();
        let request_v1 = runne_api::ProtectedLaunchRequestV1::new(
            *uuid::Uuid::now_v7().as_bytes(),
            *uuid::Uuid::now_v7().as_bytes(),
            runne_api::LaunchSecret::from_bytes([3; 32]).unwrap(),
            10,
            20,
            "permission-v2-test",
            profile.clone(),
            runne_api::ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
            std::path::PathBuf::from("/tmp/runtime"),
            runne_api::ActivationDispositionV1::FirstActivation,
        )
        .unwrap();
        let keys = request_v1.derive_keys();
        let stable = runne_api::StableRuntimeBindingV1::new(
            *uuid::Uuid::now_v7().as_bytes(),
            "permission-v2-test",
            *uuid::Uuid::now_v7().as_bytes(),
            profile.profile_id(),
            *profile.profile_hash(),
            *profile.capability_digest(),
        )
        .unwrap();
        let mut ready_v1 = runne_api::ProtectedReadyV1::new(
            request_v1.launch_authority_id(),
            request_v1.desktop_host_instance_id(),
            request_v1.executable().clone(),
            profile,
            stable,
            *uuid::Uuid::now_v7().as_bytes(),
            1,
            *uuid::Uuid::now_v7().as_bytes(),
            "https://127.0.0.1:43123",
            [6; 32],
            vec![7; 32],
            vec!["provider.execute".to_owned()],
        )
        .unwrap();
        ready_v1.sign(&keys);
        let provider = runne_api::ProviderActivationBindingV1::openai_responses_text_v1();
        let request =
            runne_api::ProtectedLaunchRequestV2::new(request_v1, provider.clone()).unwrap();
        let mut ready = runne_api::ProtectedReadyV2::new(
            ready_v1,
            provider,
            runne_api::ProviderActivationReadinessV1::CredentialMissing,
        )
        .unwrap();
        ready.sign(&keys);
        let owned = ready.owned_launch();
        (
            ProtectedProcessActivation::V2 {
                request,
                ready,
                owned: owned.clone(),
            },
            keys,
            owned,
        )
    }

    fn pending(
        owned: &runne_api::ProtectedOwnedLaunchV2,
        keys: &runne_api::ProtectedActivationKeys,
    ) -> PermissionModeNativePendingV2 {
        let base = owned.compatibility_owned_launch();
        let principal = ApiPrincipalId::new(base.stable().principal_id().to_owned()).unwrap();
        let now = unix_millis().unwrap();
        PermissionModeNativePendingV2 {
            workspace_id: uuid::Uuid::now_v7().to_string(),
            principal_id: principal.as_str().to_owned(),
            context: runne_api::PermissionModeNativePendingContextV2 {
                runtime_authority: hex::encode(base.stable().authority_id()),
                store_lineage_id: *base.stable().lineage_id(),
                stable_subject_digest: permission_control_stable_subject_digest_v1(&principal)
                    .unwrap(),
                protected_launch_authority_id: *base.launch_authority_id(),
                desktop_authority_id: *base.desktop_host_instance_id(),
                daemon_instance_id: *base.daemon_instance_id(),
                protected_session_id: *base.session_id(),
                launch_generation: base.launch_generation(),
                native_key_epoch: keys
                    .permission_control_native_authenticator()
                    .native_key_epoch(),
                command_id: uuid::Uuid::now_v7().to_string(),
                idempotency_key: "permission-v2-renewal".to_owned(),
                public_request_digest: [8; 32],
                predecessor_transcript_digest: [0; 32],
                issued_at_unix_ms: now,
                expires_at_unix_ms: now + 20_000,
            },
        }
    }

    #[test]
    fn v2_owner_renews_and_old_session_exchange_is_fenced() {
        let (mut activation, keys, owned) = v2_activation();
        let old_pending = pending(&owned, &keys);
        let (stable, old_channel) = permission_owner_identity(&activation).unwrap();
        assert_eq!(stable.principal_id(), "permission-v2-test");
        let epoch = keys
            .permission_control_native_authenticator()
            .native_key_epoch();
        let old_owner = (
            old_channel.0,
            old_channel.1,
            old_channel.2,
            old_channel.3,
            epoch,
            old_channel.4,
        );
        assert!(exact_request_context(&old_pending, &activation, old_owner).is_ok());

        let mut renewal = runne_api::ProtectedRenewRequestV2::new(owned, 1, [9; 32]).unwrap();
        renewal.sign(&keys);
        let mut ticket = runne_api::ProtectedRenewTicketV2::new(
            &renewal,
            *uuid::Uuid::now_v7().as_bytes(),
            [10; 32],
            100,
            200,
        )
        .unwrap();
        ticket.sign(&keys);
        ticket.verify_exact(&renewal, &keys).unwrap();
        let next = ticket.next_owned_launch();
        let ProtectedProcessActivation::V2 { owned, .. } = &mut activation else {
            panic!("V2 fixture")
        };
        *owned = next;
        let (_, new_channel) = permission_owner_identity(&activation).unwrap();
        let new_owner = (
            new_channel.0,
            new_channel.1,
            new_channel.2,
            new_channel.3,
            epoch,
            new_channel.4,
        );
        assert!(same_permission_channel(&old_owner, &new_owner));
        assert_ne!(old_owner.5, new_owner.5);
        assert!(exact_request_context(&old_pending, &activation, new_owner).is_err());

        let context = old_pending.context.control_context().unwrap();
        let challenge = PermissionControlModeChallengeV1 {
            principal: old_pending.principal_id.clone(),
            workspace_id: *uuid::Uuid::parse_str(&old_pending.workspace_id)
                .unwrap()
                .as_bytes(),
            workspace_label: "test".to_owned(),
            expected_authorization_revision: 0,
            requested_mode: runne_api::PermissionModeSelectionV1::RiskBased,
            preset_version: 1,
            mode_expires_at_unix_ms: None,
            managed_policy_revision: 0,
            managed_policy_digest: [11; 32],
            issued_challenge_binding_digest: [12; 32],
            ceremony_expires_at_unix_ms: context.expires_at_unix_ms,
            native_warning_version: 1,
            challenge_id: *uuid::Uuid::now_v7().as_bytes(),
            nonce: [13; 32],
        };
        let mut sequence = PermissionControlSequenceV1 {
            owner: old_owner,
            last_authenticated_sequence: 4,
            active: Some(PermissionModeExchangeV1 {
                owner: old_owner,
                context,
                challenge,
            }),
        };
        rebind_permission_sequence(&mut sequence, new_owner).unwrap();
        assert_eq!(sequence.last_authenticated_sequence, 4);
        assert!(sequence.active.is_none());
        assert_eq!(sequence.owner, new_owner);

        let mut sequence = PermissionControlSequenceV1 {
            owner: new_owner,
            last_authenticated_sequence: 4,
            active: None,
        };
        rebind_permission_sequence(
            &mut sequence,
            (
                new_owner.0,
                new_owner.1,
                new_owner.2,
                new_owner.3,
                new_owner.4 + 1,
                new_owner.5,
            ),
        )
        .unwrap();
        assert_eq!(sequence.last_authenticated_sequence, 0);
    }
}
