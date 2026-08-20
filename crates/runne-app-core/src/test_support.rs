//! Test-only protected bundled runtime fixtures.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use runne_runtime_client::{
    CanonicalId, GOLDEN_BUNDLE_HASH, PROTECTED_RUNTIME_CAPABILITIES, ReplayAggregateKind,
    ReplayIdentityTracker, ReplayScope, RuntimeSessionInfo,
    mock_protected_authenticated_runtime_client,
};
use runne_secure_store::SecureStore;

use crate::{AppCore, AppCoreError};

/// Opens an anchored external-local core using an explicit test runtime profile.
///
/// This preserves the production mutation-admission boundary while allowing
/// real-process tests to use an isolated daemon-owned profile file.
///
/// # Errors
///
/// Returns a closed error when the anchored local store cannot be admitted.
pub fn open_anchored_external_local_core(
    database_path: &Path,
    runtime_profile_path: PathBuf,
    secure: Arc<dyn SecureStore>,
    profile: [u8; 32],
) -> Result<AppCore, AppCoreError> {
    let store =
        runne_local_store::LocalStore::open_anchored(database_path, secure.as_ref(), profile)
            .map_err(|_| AppCoreError::MutationUnavailable)?;
    Ok(AppCore::open_store(
        store,
        crate::RuntimeMode::ExternalLocal,
        Some(runtime_profile_path),
        Some(crate::MutationSecurityContext { secure }),
    ))
}

/// Installs an unbound test reference after the caller has admitted its exact
/// Project and Workspace through the runtime command path.
///
/// # Errors
///
/// Returns a closed local-project or settings-store error.
pub fn install_unbound_conversation_reference_for_test(
    core: &AppCore,
    local_project_id: i64,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
) -> Result<(), AppCoreError> {
    let command_id = CanonicalId::now_v7();
    let reference = crate::StoredConversationReference::V1(crate::StoredConversationReferenceV1 {
        schema_version: 1,
        conversation_id,
        workspace_id,
        create_command_id: command_id,
        idempotency_key: command_id.to_string(),
    });
    let value = serde_json::to_string(&reference)
        .map_err(|_| AppCoreError::InvalidConversationReference)?;
    let mut store = core
        .store
        .lock()
        .map_err(|_| AppCoreError::StateUnavailable)?;
    if store.get_project(local_project_id)?.is_none() {
        return Err(AppCoreError::ProjectUnavailable);
    }
    store.set_setting(
        &format!("runtime.conversation.project.{local_project_id}"),
        &value,
    )?;
    drop(store);
    Ok(())
}

/// Exercises the aggregate-neutral V2 promotion coordinator for `TaskRun`
/// without exposing a `TaskRun` renderer surface.
///
/// # Errors
///
/// Returns the exact closed replay or local-persistence error.
pub async fn promote_task_run_v2_for_test(
    core: &AppCore,
    task_run_id: runne_runtime_client::CanonicalId,
) -> Result<(), AppCoreError> {
    let context = core.live_runtime_operation_context()?;
    let scope = ReplayScope::new(ReplayAggregateKind::TaskRun, task_run_id);
    let scope_key = runne_local_store::ReplayScopeKey {
        runtime_authority: context.identity.authority.clone(),
        principal: context.identity.principal.clone(),
        lineage: context.identity.lineage.clone(),
        scope: format!("task_run:{task_run_id}"),
        binding_digest: context.identity.binding_digest.clone(),
    };
    let result = context
        .client
        .catch_up_from_persisted_cursor(
            scope,
            Some("gocode-replay-cursor-v1.7b7d"),
            ReplayIdentityTracker::new(),
            |_| Ok::<(), ()>(()),
            |()| {},
        )
        .await;
    let Err(error) = result else {
        return Err(AppCoreError::RuntimeIncompatible);
    };
    let baseline = error
        .retention_baseline_v2()
        .ok_or(AppCoreError::RuntimeIncompatible)?;
    core.promote_retention_baseline_v2_under_operation(&context, scope, &scope_key, None, baseline)
        .await
}

/// Opens an anchored bundled core with one exact protected loopback runtime.
///
/// # Errors
///
/// Returns a closed error for a non-loopback or zero-port endpoint, storage
/// admission failure, or invalid bundled runtime lifecycle transition.
pub async fn open_protected_bundled_workspace_core(
    database_path: &Path,
    address: SocketAddr,
) -> Result<AppCore, AppCoreError> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(AppCoreError::RuntimeUnavailable);
    }
    let profile = [0x86; 32];
    let capabilities = PROTECTED_RUNTIME_CAPABILITIES
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let secure = Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile));
    let core = AppCore::open_bundled_anchored(database_path, secure, profile)?;
    let lease = core.begin_bundled_runtime_start().await?;
    let client = mock_protected_authenticated_runtime_client(
        &format!("http://{address}"),
        RuntimeSessionInfo {
            profile_id: "gocode-ui-client/2".into(),
            schema_hash: GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capabilities: capabilities.clone(),
            authority_id: "authority".into(),
            principal_id: "principal".into(),
            event_log_lineage_id: "lineage".into(),
            daemon_instance_id: "daemon".into(),
            launch_generation: 1,
            session_id: "session".into(),
            authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(),
            certificate_sha256: "11".repeat(32),
            capability_digest: protected_capability_digest(&capabilities),
        },
    )
    .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    core.install_bundled_runtime_client(lease, client).await?;
    Ok(core)
}

fn protected_capability_digest(capabilities: &[String]) -> String {
    use sha2::Digest;

    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(
        u32::try_from(capabilities.len())
            .expect("capability count")
            .to_be_bytes(),
    );
    for capability in capabilities {
        digest.update(
            u32::try_from(capability.len())
                .expect("capability length")
                .to_be_bytes(),
        );
        digest.update(capability.as_bytes());
    }
    hex::encode(digest.finalize())
}
