use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use runne_api::{
    ApiActor, ApiPrincipalId, BeginProviderCredentialEnrollment,
    ProviderCredentialBaseRequestAuthority, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostPort, ProviderCredentialHostFuture,
    ProviderCredentialIntentConsumptionProof, ProviderCredentialOperationHandleV2,
    ProviderCredentialOperationKindV2, ProviderCredentialOperationSnapshotV2,
    ProviderCredentialOperationStateV2, ProviderCredentialProviderV2,
    ProviderCredentialRequestAuthorityPair, ProviderCredentialSafeSnapshotV2,
    ProviderCredentialStateV2, ProviderCredentialStatusFuture,
    ProviderCredentialVerificationStateV2, VerifyProviderCredential,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use tower::ServiceExt;

use super::{
    ProviderCredentialEnrollmentHttpAdmission, ProviderCredentialEnrollmentHttpAdmissionResolver,
    ProviderCredentialEnrollmentHttpState, provider_credential_enrollment_router,
    provider_credential_enrollment_router_for_provider,
};

mod resolver_support;

struct Resolver;

impl ProviderCredentialEnrollmentHttpAdmissionResolver for Resolver {
    fn resolve_begin(
        &self,
        session: [u8; 16],
        _: &BeginProviderCredentialEnrollment,
    ) -> Result<
        Arc<ProviderCredentialEnrollmentHttpAdmission>,
        runne_api::ProviderCredentialEnrollmentHostError,
    > {
        (session == [5; 16])
            .then(mutation_admission)
            .ok_or(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn resolve_verify(
        &self,
        _: [u8; 16],
        _: &VerifyProviderCredential,
    ) -> Result<
        Arc<ProviderCredentialEnrollmentHttpAdmission>,
        runne_api::ProviderCredentialEnrollmentHostError,
    > {
        Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn resolve_status(
        &self,
        session: [u8; 16],
        _: &ProviderCredentialProviderV2,
    ) -> Result<
        Arc<ProviderCredentialEnrollmentHttpAdmission>,
        runne_api::ProviderCredentialEnrollmentHostError,
    > {
        (session == [5; 16])
            .then(base_admission)
            .ok_or(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn resolve_resume(
        &self,
        _: [u8; 16],
        _: ProviderCredentialOperationHandleV2,
    ) -> Result<
        Arc<ProviderCredentialEnrollmentHttpAdmission>,
        runne_api::ProviderCredentialEnrollmentHostError,
    > {
        Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

struct Host {
    calls: Arc<AtomicUsize>,
}

impl ProviderCredentialEnrollmentHostPort for Host {
    fn begin<'a>(
        &'a self,
        _: ProviderCredentialBaseRequestAuthority,
        _: ProviderCredentialIntentConsumptionProof,
        _: ProviderCredentialCommandContext,
        command: BeginProviderCredentialEnrollment,
    ) -> ProviderCredentialHostFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(operation_for(command.provider())) })
    }

    fn resume<'a>(
        &'a self,
        _: ProviderCredentialBaseRequestAuthority,
        _: ProviderCredentialCommandContext,
        _: ProviderCredentialOperationHandleV2,
    ) -> ProviderCredentialHostFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(operation()) })
    }

    fn status<'a>(
        &'a self,
        _: ProviderCredentialBaseRequestAuthority,
        provider: ProviderCredentialProviderV2,
    ) -> ProviderCredentialStatusFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(status_for(provider)) })
    }

    fn verify<'a>(
        &'a self,
        _: ProviderCredentialBaseRequestAuthority,
        _: ProviderCredentialIntentConsumptionProof,
        _: ProviderCredentialCommandContext,
        command: VerifyProviderCredential,
    ) -> ProviderCredentialHostFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(operation_for(command.provider())) })
    }
}

fn router() -> (Router, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let router =
        provider_credential_enrollment_router(ProviderCredentialEnrollmentHttpState::new(Host {
            calls: Arc::clone(&calls),
        }));
    (router, calls)
}

fn context() -> ProviderCredentialCommandContext {
    ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes([1; 16]),
        idempotency_key: IdempotencyKey::new("http-idempotency").unwrap(),
        principal: ApiPrincipalId::new("http-principal").unwrap(),
        actor: ApiActor::new("http-actor").unwrap(),
    }
}

fn mutation_admission() -> Arc<ProviderCredentialEnrollmentHttpAdmission> {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    ProviderCredentialEnrollmentHttpAdmission::mutation(
        issuer
            .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
            .unwrap(),
        issuer
            .issue_intent_proof([6; 32], [3; 32], [7; 32], [8; 32], 100)
            .unwrap(),
        context(),
    )
}

fn base_admission() -> Arc<ProviderCredentialEnrollmentHttpAdmission> {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    ProviderCredentialEnrollmentHttpAdmission::base(
        issuer
            .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
            .unwrap(),
        context(),
    )
}

fn begin_request(
    admission: Option<Arc<ProviderCredentialEnrollmentHttpAdmission>>,
) -> Request<Body> {
    let mut request = Request::post("/v2/provider-credential-enrollment")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"action":"pair","provider":"openai","expectedLifecycleRevision":1,"commandIdentity":"018f8d23-7f90-7c00-8000-000000000001","idempotencyKey":"idempotency-a","nativeIntentId":"intent-a"}"#,
        ))
        .unwrap();
    if let Some(admission) = admission {
        request.extensions_mut().insert(admission);
    }
    request
}

fn operation() -> ProviderCredentialOperationSnapshotV2 {
    operation_for(ProviderCredentialProviderV2::OpenAi)
}

fn operation_for(provider: ProviderCredentialProviderV2) -> ProviderCredentialOperationSnapshotV2 {
    ProviderCredentialOperationSnapshotV2::new(
        ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
        None,
        provider,
        ProviderCredentialOperationKindV2::VerifyLocal,
        ProviderCredentialOperationStateV2::Completed,
        1,
        1,
        false,
        None,
    )
    .unwrap()
}

fn status_for(provider: ProviderCredentialProviderV2) -> ProviderCredentialSafeSnapshotV2 {
    ProviderCredentialSafeSnapshotV2::new(
        provider,
        ProviderCredentialStateV2::Missing,
        runne_api::ProviderCredentialReadinessV2::Missing,
        1,
        1,
        1,
        ProviderCredentialVerificationStateV2::NotVerified,
        0,
        None,
        false,
        None,
    )
    .unwrap()
}

include!("tests_cases.inc");
