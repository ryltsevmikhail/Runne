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
        _: BeginProviderCredentialEnrollment,
    ) -> ProviderCredentialHostFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(operation()) })
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
        _: ProviderCredentialProviderV2,
    ) -> ProviderCredentialStatusFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(status()) })
    }

    fn verify<'a>(
        &'a self,
        _: ProviderCredentialBaseRequestAuthority,
        _: ProviderCredentialIntentConsumptionProof,
        _: ProviderCredentialCommandContext,
        _: VerifyProviderCredential,
    ) -> ProviderCredentialHostFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(operation()) })
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
    ProviderCredentialOperationSnapshotV2::new(
        ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
        None,
        ProviderCredentialProviderV2::OpenAi,
        ProviderCredentialOperationKindV2::VerifyLocal,
        ProviderCredentialOperationStateV2::Completed,
        1,
        1,
        false,
        None,
    )
    .unwrap()
}

fn status() -> ProviderCredentialSafeSnapshotV2 {
    ProviderCredentialSafeSnapshotV2::new(
        ProviderCredentialProviderV2::OpenAi,
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

#[tokio::test]
async fn unadmitted_begin_is_forbidden_without_a_host_call() {
    let (router, calls) = router();

    let response = router.oneshot(begin_request(None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn admission_is_consumed_once_and_never_created_from_json() {
    let (router, calls) = router();
    let admission = mutation_admission();

    let accepted = router
        .clone()
        .oneshot(begin_request(Some(Arc::clone(&admission))))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let replay = router
        .oneshot(begin_request(Some(admission)))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn daemon_resolver_requires_the_authenticated_runtime_session() {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = provider_credential_enrollment_router(
        ProviderCredentialEnrollmentHttpState::with_admission_resolver(
            Host {
                calls: Arc::clone(&calls),
            },
            Resolver,
        ),
    );
    let mut request = begin_request(None);
    request
        .extensions_mut()
        .insert(resolver_support::authenticated_session());
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn begin_rejects_credential_material_before_the_host() {
    let (router, calls) = router();
    let mut request = begin_request(Some(mutation_admission()));
    *request.body_mut() = Body::from(
        r#"{"action":"pair","provider":"openai","expectedLifecycleRevision":1,"commandIdentity":"018f8d23-7f90-7c00-8000-000000000001","idempotencyKey":"idempotency-a","nativeIntentId":"intent-a","credential":"secret"}"#,
    );

    let response = router.oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), 1024).await.unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("provider_credential_invalid_request")
    );
}

#[tokio::test]
async fn admitted_status_is_dynamically_delegated_to_the_host() {
    let (router, calls) = router();
    let mut request = Request::get("/v2/providers/openai/credential-enrollment")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(base_admission());

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

fn resolver_router() -> (Router, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = provider_credential_enrollment_router(
        ProviderCredentialEnrollmentHttpState::with_admission_resolver(
            Host {
                calls: Arc::clone(&calls),
            },
            Resolver,
        ),
    );
    (router, calls)
}

#[tokio::test]
async fn daemon_resolver_derives_status_from_the_authenticated_session() {
    let (router, calls) = resolver_router();
    let mut request = Request::get("/v2/providers/openai/credential-enrollment")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(resolver_support::authenticated_session());

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn resolver_status_fails_closed_without_an_authenticated_session() {
    let (router, calls) = resolver_router();
    let request = Request::get("/v2/providers/openai/credential-enrollment")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
