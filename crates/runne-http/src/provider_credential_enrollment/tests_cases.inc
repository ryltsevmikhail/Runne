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
