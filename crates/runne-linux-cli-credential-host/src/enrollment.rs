use super::{
    measurements::{binding, seal},
    policy::{HostResult, ImagePolicy},
};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::*;
use runne_secure_store::{
    NativeProviderCredentialStore, NativeProviderCredentialVersionStore,
    ProviderCredentialMaterial, ProviderCredentialStatus,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use std::sync::Arc;

pub(super) fn pair(
    bootstrap: runne_daemon::bootstrap::BootstrapOutcome,
    policy: Arc<ImagePolicy>,
    material: ProviderCredentialMaterial,
) -> HostResult<()> {
    let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
    let (enrollment, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = Arc::new(
        SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
            bootstrap.db_conn,
            lifecycle.clone(),
            enrollment,
        )
        .map_err(|_| "credential lifecycle unavailable")?,
    );
    let native = NativeProviderCredentialStore::new_cli_host_versioned(
        native_authority,
        bootstrap.authority_id,
    );
    let result = pair_with(
        store,
        lifecycle,
        measurements,
        &native,
        policy,
        bootstrap.authority_id,
        bootstrap.launch_generation,
        material,
    );
    drop(bootstrap.locks);
    result
}

#[allow(clippy::too_many_arguments)]
fn pair_with(
    store: Arc<SqliteProviderCredentialLifecycleStore>,
    lifecycle: CredentialLifecycleAuthority,
    measurements: CredentialEnrollmentMeasurementAuthority,
    native: &dyn NativeProviderCredentialVersionStore,
    policy: Arc<ImagePolicy>,
    runtime: [u8; 16],
    generation: u64,
    material: ProviderCredentialMaterial,
) -> HostResult<()> {
    let provider = ProviderId::new("deepseek").map_err(|_| "invalid provider")?;
    let before = store
        .begin_admission_snapshot(&provider)
        .map_err(|_| "credential admission unavailable")?;
    let reference = CredentialVersionRef::new(provider.clone(), before.next_credential_version())
        .map_err(|_| "credential allocation unavailable")?;
    let nonce = *uuid::Uuid::now_v7().as_bytes();
    let operation =
        CredentialOperationId::from_bytes(nonce).map_err(|_| "operation identity unavailable")?;
    let installation = measurements
        .cli_host_installation_binding(policy.manifest)
        .map_err(|_| "CLI installation binding unavailable")?;
    let installation_digest = installation.digest();
    let admitted_at = now()?;
    let deadline = admitted_at
        .checked_add(180)
        .ok_or("credential deadline overflow")?;
    let begin = BeginCredentialOperation::new(
        CommandId::from_bytes(nonce),
        IdempotencyKey::new(format!("cli-deepseek-{}", uuid::Uuid::from_bytes(nonce)))
            .map_err(|_| "invalid command")?,
        operation,
        CredentialInstallationOwnerId::from_bytes(super::measurements::hash(
            b"installation-owner",
            &runtime,
        ))
        .map_err(|_| "owner binding unavailable")?,
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(reference.clone()),
        None,
        before.lifecycle_revision(),
        before.fence(),
        binding(b"human-tty-consent", &nonce)?,
        deadline as u64,
    )
    .map_err(|_| "credential begin rejected")?
    .with_cli_host_installation(installation)
    .map_err(|_| "CLI installation rejected")?;
    policy.revalidate()?;
    let admitted = store
        .begin(begin)
        .map_err(|_| "credential begin rejected; no key was stored")?;
    if !admitted.is_fresh_winner() {
        return Err("credential operation already exists");
    }
    let continuation = binding(b"continuation", &nonce)?;
    let ticket = binding(b"ticket", &nonce)?;
    store
        .attach_process(
            AttachCredentialProcess::new(operation, continuation)
                .map_err(|_| "invalid continuation")?,
        )
        .map_err(|_| "credential process attachment rejected")?;
    let issued = store
        .issue_ticket_attempt(
            IssueCredentialTicketDigest::new(operation, ticket, continuation, 120)
                .map_err(|_| "invalid ticket")?,
        )
        .map_err(|_| "credential ticket rejected")?;
    let draft = ClaimCredentialOperation::new(
        issued,
        ticket,
        continuation,
        binding(b"draft", &nonce)?,
        generation,
        generation,
    )
    .map_err(|_| "credential claim rejected")?;
    store
        .claim(seal(
            &measurements,
            &policy,
            runtime,
            installation_digest,
            draft,
        )?)
        .map_err(|_| "credential claim rejected")?;

    let access = policy.access()?;
    if native
        .version_status(&reference, &access)
        .map_err(|_| "native credential backend unavailable")?
        != ProviderCredentialStatus::Missing
    {
        return Err("allocated native credential version already exists");
    }
    store
        .mark_native_effect_observed(ObserveNativeEffect::new(
            operation,
            CredentialNativeEffectDisposition::PossibleEffect,
        ))
        .map_err(|_| "native effect admission rejected")?;
    let validator = Arc::new(CreateValidator {
        store: store.clone(),
        policy: policy.clone(),
        operation,
        reference: reference.clone(),
        deadline,
        revision: before.lifecycle_revision(),
        fence: before.fence(),
    });
    let source = lifecycle
        .issue_provision_source(nonce)
        .map_err(|_| "credential source rejected")?;
    let claim = lifecycle
        .native_create_issuer()
        .map_err(|_| "native issuer unavailable")?
        .issue_native_create(reference.clone(), &source, validator)
        .map_err(|_| "native create rejected")?;
    native
        .create_version(claim, &material, &access)
        .map_err(|_| "native write unconfirmed; operation retained for reconciliation")?;
    drop(material);
    policy.revalidate()?;
    if native
        .version_status(&reference, &access)
        .map_err(|_| "native readback unavailable")?
        != ProviderCredentialStatus::Configured
    {
        return Err("native readback did not confirm the exact version");
    }
    let revision = native
        .version_source_revision(&reference, &access)
        .map_err(|_| "native revision unavailable")?;
    if revision.as_bytes() != &nonce {
        return Err("native source revision mismatch");
    }
    let readback = BindCredentialReadback::new(
        operation,
        CredentialReadbackDisposition::ExactVersion,
        binding(b"native-readback", revision.as_bytes())?,
    )
    .map_err(|_| "invalid readback")?;
    store
        .bind_readback(
            BindCredentialReadback::new(
                operation,
                CredentialReadbackDisposition::ExactVersion,
                binding(b"native-readback", revision.as_bytes())?,
            )
            .map_err(|_| "invalid readback")?,
        )
        .map_err(|_| "native readback binding rejected")?;
    let readiness = CredentialReadinessObservation::new(
        CredentialOperationId::from_bytes(*uuid::Uuid::now_v7().as_bytes())
            .map_err(|_| "readiness identity unavailable")?,
        Some(operation),
        provider,
        CredentialLifecycleRevision::new(before.lifecycle_revision().get() + 1)
            .map_err(|_| "revision overflow")?,
        CredentialReadinessRevision::new(before.readiness_revision().get() + 1)
            .map_err(|_| "revision overflow")?,
        CredentialReadinessDisposition::Ready,
        Some(
            CredentialBindingDigest::from_measured(*reference.ref_digest())
                .map_err(|_| "invalid reference")?,
        ),
        installation_digest,
        now()?,
    )
    .map_err(|_| "readiness observation rejected")?;
    policy.revalidate()?;
    store
        .complete(
            CompleteCredentialOperation::new(
                operation,
                readback,
                before.lifecycle_revision(),
                before.fence(),
            )
            .map_err(|_| "invalid completion")?
            .with_readiness_observation(readiness),
        )
        .map_err(|_| "credential activation unconfirmed; operation retained for reconciliation")?;
    Ok(())
}

struct CreateValidator {
    store: Arc<SqliteProviderCredentialLifecycleStore>,
    policy: Arc<ImagePolicy>,
    operation: CredentialOperationId,
    reference: CredentialVersionRef,
    deadline: i64,
    revision: CredentialLifecycleRevision,
    fence: CredentialFence,
}
impl CredentialNativeCreateValidator for CreateValidator {
    fn validate(&self) -> Result<(), CredentialLifecycleError> {
        self.policy
            .revalidate()
            .map_err(|_| CredentialLifecycleError::StaleLease)?;
        if now().map_err(|_| CredentialLifecycleError::StaleLease)? >= self.deadline {
            return Err(CredentialLifecycleError::StaleLease);
        }
        let head = self
            .store
            .begin_admission_snapshot(self.reference.provider())?;
        if head.lifecycle_revision() != self.revision || head.fence() != self.fence {
            return Err(CredentialLifecycleError::StaleLease);
        }
        let operation = self.store.load_operation(self.operation)?;
        if operation.state() != CredentialOperationState::NativeEffectObserved
            || operation.allocated_credential_version() != Some(&self.reference)
        {
            return Err(CredentialLifecycleError::StaleLease);
        }
        Ok(())
    }
}
pub(super) fn now() -> HostResult<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_secs()).ok())
        .ok_or("clock unavailable")
}

#[cfg(test)]
#[path = "enrollment_tests.rs"]
mod tests;
