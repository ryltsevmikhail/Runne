use std::sync::atomic::{AtomicUsize, Ordering};

use futures::executor::block_on;
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::provider::{ProviderCoordinatorRequest, ProviderLeaseBindingKind};
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, ModelRef, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallId, ProviderFuture, ProviderId, ProviderPort,
    ProviderStreamId, ProviderStreamItem, ReconcileRequest, ReconciliationDisposition,
    StreamCursor, StreamError,
};

use super::super::{
    CredentialDispatchBinding, ProviderCoordinatorOutcome, ProviderEffectPort,
    ProviderEffectStartReceipt, ProviderReadyEffect, ProviderRuntimeAuthorityConfig,
    SqliteProviderDispatchCoordinator, SqliteProviderDispatchStore,
};
use super::SqliteProviderExecutionStore;
use super::authority_test_support::configured_connection;
use crate::provider::credential_lifecycle::online_claim_test_support::open_test_store;
use crate::provider::credential_lifecycle::online_test_support::complete_pair;

struct Ready;
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

#[derive(Default)]
struct Provider {
    stages: AtomicUsize,
    sends: AtomicUsize,
}

impl ProviderPort for Provider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: runne_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { unreachable!() })
    }
    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
}

impl ProviderEffectPort for Provider {
    fn stage_effect(
        &self,
        _: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        self.stages.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        mut receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            receipt
                .take_final_send_authority()
                .map_err(|_| DispatchError::MaybeDispatched)?
                .consume()
                .map_err(|_| {
                    DispatchError::RejectedBeforeEffect(
                        runne_provider::ProviderPreEffectRejection::AdapterRejected,
                    )
                })?;
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(ProviderStreamId::from_bytes([1; 16]))
        })
    }
}

struct Guard;
impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

#[test]
fn lost_effect_readback_freezes_before_stage2_send() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join("provider.sqlite");
    let path_text = path.to_str().unwrap();
    let credential = open_test_store(&path, 100);
    complete_pair(&credential, 91, "coordinator-online");
    let (conversation_id, taskrun_id, execution_attempt_id) =
        super::canonical_started_test_support::seed(&path, 91);
    let dispatch =
        SqliteProviderDispatchStore::open_with_connection(path_text, configured_connection(&path))
            .unwrap();
    let execution =
        SqliteProviderExecutionStore::open_with_connection(path_text, configured_connection(&path))
            .unwrap();
    let config = ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 1,
        principal_id: "principal-1".into(),
        owner_id: "owner".into(),
        scope: "provider.dispatch".into(),
        generation: 1,
        fencing_token: 1,
        capability_grant_id: "grant".into(),
        capability_revision: 1,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval".into(),
        approval_revision: 1,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    };
    let launch = execution.activate_runtime_launch(&config).unwrap();
    super::online_proof_test_support::arm_for_authority(
        &execution,
        config.runtime_authority_id,
        config.database_generation,
    );
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(ProviderId::new("openai").unwrap(), "model", "2026-08-01").unwrap(),
        [5; 32],
        64,
        serde_json::Value::Null,
    )
    .unwrap();
    execution.fail_next_effect_readback();
    let provider = Provider::default();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        crate::provider::CredentialDispatchAuthority::new(&credential, &launch),
        &provider,
        &provider,
        &Guard,
    );
    let outcome = block_on(coordinator.dispatch(ProviderCoordinatorRequest {
        call,
        principal_id: "principal-1".into(),
        conversation_id,
        taskrun_id,
        execution_attempt_id,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 32,
        requested_output_tokens: 64,
        max_cost_micros: 10_000,
        currency: "USD".into(),
        provider_idempotency_key: "provider-coordinator".into(),
    }))
    .unwrap();
    assert_eq!(outcome, ProviderCoordinatorOutcome::Uncertain);
    assert_eq!(provider.stages.load(Ordering::SeqCst), 1);
    assert_eq!(provider.sends.load(Ordering::SeqCst), 0);
    let state: i64 = rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT state FROM provider_dispatch_attempts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(state, 6);
    let durable: (i64, i64, i64) = rusqlite::Connection::open(daemon.join("provider.sqlite"))
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_effect_starts),
                (SELECT COUNT(*) FROM provider_online_credential_effect_bindings),
                (SELECT COUNT(*) FROM security_audit_pre_effect)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (1, 1, 1));
}
