use super::model::{
    AdminError, CurrentPolicyAdmin, PolicyAdminBootstrapEvidence, PolicyAdminSessionBinding,
    VerifiedPolicyAdminAuthorityFacts, VerifiedPolicyAdminBootstrap,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Trusted native verifier for retained protected-bootstrap evidence.
///
/// Production composition must pin the daemon-owned implementation. Tests may
/// use a mock; a caller-provided implementation is not production authority.
pub trait PolicyAdminBootstrapVerifier: Send + Sync {
    /// Accept only retained protected evidence for the fixed administrator role.
    fn verify_retained_protected_bootstrap(
        &self,
        evidence: &PolicyAdminBootstrapEvidence,
    ) -> Result<(), AdminError>;
}

/// Session owner whose mutex remains held while its callback runs.
///
/// The production daemon adapter must compare the entire expected binding and
/// retain its existing session-rotation mutex across the callback. This port is
/// intentionally not wired to a production host in this draft.
pub trait PolicyAdminAuthoritySource: Send + Sync {
    /// Supply current retained evidence while holding the session rotation lock.
    fn with_current_evidence(
        &self,
        expected: &PolicyAdminSessionBinding,
        callback: &mut dyn FnMut(&PolicyAdminBootstrapEvidence) -> Result<(), AdminError>,
    ) -> Result<(), AdminError>;
}

/// Verifies retained evidence before exposing private current authority facts.
pub struct PolicyAdminAuthorityVerifier<'a> {
    bootstrap: &'a dyn PolicyAdminBootstrapVerifier,
    source: &'a dyn PolicyAdminAuthoritySource,
}

impl<'a> PolicyAdminAuthorityVerifier<'a> {
    /// Creates an adapter over the trusted daemon bootstrap and session owners.
    pub const fn new(
        bootstrap: &'a dyn PolicyAdminBootstrapVerifier,
        source: &'a dyn PolicyAdminAuthoritySource,
    ) -> Self {
        Self { bootstrap, source }
    }

    /// Verifies exactly one current full binding while the source lock stays held.
    pub fn with_current(
        &self,
        expected: &PolicyAdminSessionBinding,
        callback: &mut dyn FnMut(&VerifiedPolicyAdminAuthorityFacts) -> Result<(), AdminError>,
    ) -> Result<(), AdminError> {
        let mut called = 0_u8;
        let result = self
            .source
            .with_current_evidence(expected, &mut |evidence| {
                called = called.saturating_add(1);
                if called != 1 || evidence.binding() != expected {
                    return Err(AdminError::CallbackContract);
                }
                let verified = verify_policy_admin_bootstrap(evidence, self.bootstrap)?;
                let facts = VerifiedPolicyAdminAuthorityFacts::from_verified_bootstrap(&verified);
                callback(&facts)
            });
        if called != 1 && result.is_ok() {
            return Err(AdminError::CallbackContract);
        }
        result
    }
}

/// Verifies one retained protected bootstrap and creates a private app proof.
pub fn verify_policy_admin_bootstrap(
    evidence: &PolicyAdminBootstrapEvidence,
    verifier: &dyn PolicyAdminBootstrapVerifier,
) -> Result<VerifiedPolicyAdminBootstrap, AdminError> {
    let binding = evidence.binding();
    if evidence.installation_provenance() == &[0; 32]
        || evidence.retained_bootstrap_handle() == &[0; 32]
        || binding.protected_launch_id() == &[0; 16]
        || binding.desktop_generation_key() == &[0; 32]
        || binding.session_key_epoch() == 0
        || binding.session_expires_at_unix_ms() <= now_unix_ms()
        || binding.runtime().canonical_digest() == [0; 32]
    {
        return Err(AdminError::Rejected);
    }
    verifier.verify_retained_protected_bootstrap(evidence)?;
    Ok(VerifiedPolicyAdminBootstrap {
        binding: binding.clone(),
        installation_provenance: *evidence.installation_provenance(),
    })
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

/// Runs one operation with an invariant, closure-local current-policy witness.
///
/// A verifier that errors or calls twice after the first action may have run
/// after a durable commit. The caller must reconcile by retrying the same ID.
pub fn with_verified_policy_admin<R>(
    verifier: &PolicyAdminAuthorityVerifier<'_>,
    expected: &PolicyAdminSessionBinding,
    operation: impl for<'a> FnOnce(&'a CurrentPolicyAdmin<'a>) -> Result<R, AdminError>,
) -> Result<R, AdminError> {
    let mut operation = Some(operation);
    let mut operation_result = None;
    let mut called = 0_u8;
    let verifier_result = verifier.with_current(expected, &mut |facts| {
        called = called.saturating_add(1);
        if called != 1 || facts.binding != *expected {
            return Err(AdminError::CallbackContract);
        }
        let witness = CurrentPolicyAdmin::new(facts);
        let action = operation.take().ok_or(AdminError::CallbackContract)?;
        operation_result = Some(action(&witness));
        Ok(())
    });

    if called == 0 {
        return Err(verifier_result
            .err()
            .unwrap_or(AdminError::CallbackContract));
    }
    if called > 1 {
        return match operation_result {
            Some(Ok(_)) | Some(Err(AdminError::UnknownAfterAction)) => {
                Err(AdminError::UnknownAfterAction)
            }
            _ => Err(AdminError::CallbackContract),
        };
    }
    if let Err(error) = verifier_result {
        return match operation_result {
            Some(Ok(_)) | Some(Err(AdminError::UnknownAfterAction)) => {
                Err(AdminError::UnknownAfterAction)
            }
            Some(Err(action_error)) => Err(action_error),
            None => Err(error),
        };
    }
    operation_result.ok_or(AdminError::CallbackContract)?
}
