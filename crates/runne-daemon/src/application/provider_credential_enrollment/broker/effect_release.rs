use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{CredentialBrokerFrame, CredentialBrokerFrameCodec};
use zeroize::Zeroizing;

use super::{ClaimedBrokerEffect, CredentialBrokerChannel, ProviderCredentialBroker};

impl ProviderCredentialBroker {
    pub(crate) fn release_control_only_effect<C: CredentialBrokerChannel>(
        &self,
        claimed: &ClaimedBrokerEffect,
        expected: runne_provider::CredentialOperationId,
        store: &dyn runne_provider::ProviderCredentialEnrollmentStore,
        channel: &mut C,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        use runne_provider::{CredentialOperationAction, CredentialOperationState};
        if claimed.operation_id != expected
            || !claimed.publication_taken
            || claimed.publication.is_some()
            || claimed.offer.is_some()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let operation = store.load_operation(expected).map_err(
            crate::application::provider_credential_enrollment::effect_authority::map_store,
        )?;
        if operation.state() != CredentialOperationState::Claimed
            || !matches!(
                operation.action(),
                CredentialOperationAction::Revoke
                    | CredentialOperationAction::RetiredVersionCleanup
                    | CredentialOperationAction::LegacySourceCleanup
            )
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.release_claimed_effect_to_channel(claimed, channel)
    }

    pub(crate) fn release_claimed_effect_to_channel<C: CredentialBrokerChannel>(
        &self,
        claimed: &ClaimedBrokerEffect,
        channel: &mut C,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        #[cfg(feature = "test-support")]
        if runne_api::test_support::local_native_enrollment_case()
            == Some(runne_api::test_support::LocalNativeEnrollmentCase::ReleaseMissing)
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let frame = CredentialBrokerFrame::NativeEffectRelease {
            operation_id: claimed.operation_id,
            attempt: claimed.attempt,
            binding: claimed.binding,
        };
        #[cfg(feature = "test-support")]
        let frame = local_faulted_release(frame)?;
        channel.send(Zeroizing::new(
            CredentialBrokerFrameCodec::encode(frame)
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        ))
    }
}

#[cfg(feature = "test-support")]
fn local_faulted_release(
    frame: CredentialBrokerFrame,
) -> Result<CredentialBrokerFrame, ProviderCredentialEnrollmentHostError> {
    use runne_api::test_support::LocalNativeEnrollmentCase;
    match runne_api::test_support::local_native_enrollment_case() {
        Some(LocalNativeEnrollmentCase::ReleaseWrong) => {
            let CredentialBrokerFrame::NativeEffectRelease {
                operation_id,
                attempt,
                mut binding,
            } = frame
            else {
                return Err(ProviderCredentialEnrollmentHostError::InvariantViolation);
            };
            let mut bytes = binding.as_bytes();
            bytes[0] ^= 0x80;
            binding = runne_provider::CredentialBindingDigest::from_measured(bytes)
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
            Ok(CredentialBrokerFrame::NativeEffectRelease {
                operation_id,
                attempt,
                binding,
            })
        }
        Some(LocalNativeEnrollmentCase::ReleaseReplayed) => {
            let CredentialBrokerFrame::NativeEffectRelease {
                attempt, binding, ..
            } = frame
            else {
                return Err(ProviderCredentialEnrollmentHostError::InvariantViolation);
            };
            let operation_id = runne_provider::CredentialOperationId::from_bytes([0xe1; 16])
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
            Ok(CredentialBrokerFrame::NativeEffectRelease {
                operation_id,
                attempt,
                binding,
            })
        }
        _ => Ok(frame),
    }
}
