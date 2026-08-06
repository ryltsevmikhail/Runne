#![allow(dead_code)]

use std::sync::Mutex;

use futures::executor::block_on;
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::provider::{ProviderAdmissionError, ProviderCoordinatorRequest};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchError, DispatchRequest, ModelRef, PrepareError, PreparedRequest, ProviderCall,
    ProviderCallId, ProviderFuture, ProviderId, ProviderPort, ProviderStreamId,
};
use gocode_store::provider::{
    ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
    ProviderRuntimeAuthorityConfig, SqliteProviderDispatchCoordinator, SqliteProviderDispatchStore,
    SqliteProviderExecutionStore,
};

#[path = "support/validated_reopen.rs"]
mod validated_reopen;

struct Ready;
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

#[derive(Clone, Copy)]
enum Denial {
    Capability,
    Approval,
    Expired,
    TokenBudget,
    CostBudget,
    Pricing,
    StaleFence,
}

impl Denial {
    fn expected(self) -> ProviderAdmissionError {
        match self {
            Self::Capability => ProviderAdmissionError::CapabilityDenied,
            Self::Approval => ProviderAdmissionError::ApprovalDenied,
            Self::Expired => ProviderAdmissionError::ApprovalDenied,
            Self::TokenBudget => ProviderAdmissionError::TokenBudgetDenied,
            Self::CostBudget => ProviderAdmissionError::CostBudgetDenied,
            Self::Pricing => ProviderAdmissionError::PricingRevisionMismatch,
            Self::StaleFence => ProviderAdmissionError::StaleFencingToken,
        }
    }
}

struct Provider(Mutex<usize>);

impl Provider {
    fn dispatched(&self) -> usize {
        *self.0.lock().unwrap()
    }
}

impl ProviderPort for Provider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: gocode_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        *self.0.lock().unwrap() += 1;
        Box::pin(async { Ok(ProviderStreamId::from_bytes([9; 16])) })
    }

    fn next<'a>(
        &'a self,
        _stream_id: &'a ProviderStreamId,
        _cursor: gocode_provider::StreamCursor,
    ) -> ProviderFuture<'a, Result<gocode_provider::ProviderStreamItem, gocode_provider::StreamError>>
    {
        Box::pin(async { unreachable!("admission test does not poll") })
    }

    fn cancel(
        &self,
        _request: gocode_provider::CancelRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("admission test does not cancel") })
    }

    fn reconcile(
        &self,
        _request: gocode_provider::ReconcileRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("admission test does not reconcile") })
    }
}

impl ProviderEffectPort for Provider {
    fn stage_effect(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        *self.0.lock().unwrap() += 1;
        Box::pin(async { Ok(ProviderStreamId::from_bytes([9; 16])) })
    }
}

struct Allowed;

impl ProhibitedContentPort for Allowed {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

fn fixture(
    denial: Denial,
) -> (
    validated_reopen::ProviderTestDatabase,
    SqliteProviderDispatchStore,
    SqliteProviderExecutionStore,
    ProviderCoordinatorRequest,
) {
    let database = validated_reopen::ProviderTestDatabase::new("provider-authority-denials");
    let dispatch = database.dispatch();
    let execution = database.execution();
    let mut config = ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 1,
        principal_id: "principal".into(),
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
        activation_binding_kind:
            gocode_application::provider::ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    };
    match denial {
        Denial::Capability => config.capability_allowed = false,
        Denial::Approval => config.approval_allowed = false,
        Denial::Expired => config.approval_allowed = false,
        Denial::TokenBudget => config.token_budget_limit = 1,
        Denial::CostBudget => config.cost_budget_limit_micros = 1,
        Denial::Pricing | Denial::StaleFence => {}
    }
    execution.install_runtime_authority(&config).unwrap();
    if matches!(denial, Denial::StaleFence) {
        execution.advance_worker_lease(2, 2).unwrap();
    }
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(ProviderId::new("fixture").unwrap(), "model", "2026-08-01").unwrap(),
        [5; 32],
        64,
        serde_json::Value::Null,
    )
    .unwrap();
    let mut request = ProviderCoordinatorRequest {
        call,
        principal_id: "principal".into(),
        conversation_id: ConversationId::from_bytes([6; 16]),
        taskrun_id: TaskRunId::from_bytes([7; 16]),
        execution_attempt_id: AttemptId::from_bytes([8; 16]),
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 32,
        requested_output_tokens: 64,
        max_cost_micros: 10_000,
        currency: "USD".into(),
        provider_idempotency_key: format!("denial-{}", denial.expected()),
    };
    if matches!(denial, Denial::Pricing) {
        request.pricing_revision_digest = [4; 32];
    }
    (database, dispatch, execution, request)
}

#[test]
fn authority_denials_never_dispatch_or_commit_a_partial_claim() {
    for denial in [
        Denial::Capability,
        Denial::Approval,
        Denial::Expired,
        Denial::TokenBudget,
        Denial::CostBudget,
        Denial::Pricing,
        Denial::StaleFence,
    ] {
        let (_directory, dispatch, execution, request) = fixture(denial);
        let provider = Provider(Mutex::new(0));
        let coordinator = SqliteProviderDispatchCoordinator::new(
            &dispatch, &execution, &provider, &provider, &Allowed,
        );
        assert_eq!(
            block_on(coordinator.dispatch(request)),
            Err(denial.expected())
        );
        assert_eq!(provider.dispatched(), 0);
        assert_eq!(execution.admitted_count().unwrap(), 0);
    }
}
