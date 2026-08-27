#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected V2 router remains unmounted until qualified admission is composed"
    )
)]

use std::sync::{Arc, Mutex};

use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostError, ProviderCredentialIntentConsumptionProof,
};

/// Per-request server-derived enrollment authority consumed by one V2 handler.
///
/// This wrapper is cloneable only through `Arc` request extensions. Its private
/// cells release the underlying values exactly once, so router cloning cannot
/// replay an accepted protected admission.
pub struct ProviderCredentialEnrollmentHttpAdmission {
    base: Mutex<Option<ProviderCredentialBaseRequestAuthority>>,
    intent: Mutex<Option<ProviderCredentialIntentConsumptionProof>>,
    context: ProviderCredentialCommandContext,
}

impl ProviderCredentialEnrollmentHttpAdmission {
    /// Creates a server-side base admission for status or resume.
    #[must_use]
    pub fn base(
        authority: ProviderCredentialBaseRequestAuthority,
        context: ProviderCredentialCommandContext,
    ) -> Arc<Self> {
        Arc::new(Self {
            base: Mutex::new(Some(authority)),
            intent: Mutex::new(None),
            context,
        })
    }

    /// Creates a server-side mutation admission for begin or verify.
    #[must_use]
    pub fn mutation(
        authority: ProviderCredentialBaseRequestAuthority,
        proof: ProviderCredentialIntentConsumptionProof,
        context: ProviderCredentialCommandContext,
    ) -> Arc<Self> {
        Arc::new(Self {
            base: Mutex::new(Some(authority)),
            intent: Mutex::new(Some(proof)),
            context,
        })
    }

    pub(super) fn take_base(
        &self,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialCommandContext,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let authority = self
            .base
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        Ok((authority, self.context.clone()))
    }

    pub(super) fn take_mutation(
        &self,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialIntentConsumptionProof,
            ProviderCredentialCommandContext,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let (authority, context) = self.take_base()?;
        let proof = self
            .intent
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        Ok((authority, proof, context))
    }
}
