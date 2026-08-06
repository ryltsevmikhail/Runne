#[path = "support.rs"]
mod support;
#[path = "task12_security.rs"]
mod task12_security;

use std::sync::{Arc, atomic::Ordering};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use bytes::Bytes;
use futures::stream;
use support::*;
use tower::ServiceExt;

#[tokio::test]
async fn protected_get_is_no_store_and_rejects_bodies() {
    let query = Arc::new(Query::new(QueryOutcome::Available));
    let (app, authorization) = app(Arc::clone(&query));
    let response = request(app.clone(), &authorization, "GET", Body::empty()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_no_store(&response);

    let response = request(app.clone(), &authorization, "GET", Body::from("x")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&response);
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );

    let response = request(
        app.clone(),
        &authorization,
        "GET",
        Body::from_stream(stream::once(async {
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(vec![0; 65_537]))
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_no_store(&response);
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );

    let response = request(app, &authorization, "POST", Body::empty()).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_no_store(&response);
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(query.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn malformed_or_nonzero_content_length_does_not_query() {
    let query = Arc::new(Query::new(QueryOutcome::Available));
    let (app, authorization) = app(Arc::clone(&query));
    for content_length in ["invalid", "1"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(PATH)
                    .header("authorization", authorization.clone())
                    .header("content-length", content_length)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_no_store(&response);
        assert!(
            to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("{PATH}?ignored"))
                .header("authorization", authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&response);
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(query.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn declared_and_chunked_body_boundaries_are_static_and_no_store() {
    let query = Arc::new(Query::new(QueryOutcome::Available));
    let (app, authorization) = app(Arc::clone(&query));
    let declared = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header("authorization", authorization.clone())
                .header("content-length", "65536")
                .body(Body::from(vec![0; 65_536]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(declared.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&declared);
    assert!(
        to_bytes(declared.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );

    let too_large = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header("authorization", authorization.clone())
                .header("content-length", "65537")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_no_store(&too_large);
    assert!(
        to_bytes(too_large.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );

    let exact = request(
        app.clone(),
        &authorization,
        "GET",
        Body::from_stream(stream::iter([
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(vec![0; 65_535])),
            Ok(Bytes::from_static(&[0])),
        ])),
    )
    .await;
    assert_eq!(exact.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&exact);
    assert!(to_bytes(exact.into_body(), 1024).await.unwrap().is_empty());

    let streamed_too_large = request(
        app.clone(),
        &authorization,
        "GET",
        Body::from_stream(stream::iter([
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(vec![0; 65_536])),
            Ok(Bytes::from_static(&[0])),
        ])),
    )
    .await;
    assert_eq!(streamed_too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_no_store(&streamed_too_large);
    assert!(
        to_bytes(streamed_too_large.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );

    let duplicate = app
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header("authorization", authorization)
                .header("content-length", "0")
                .header("content-length", "0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&duplicate);
    assert!(
        to_bytes(duplicate.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(query.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn authentication_rejects_before_the_query() {
    let query = Arc::new(Query::new(QueryOutcome::Available));
    let (app, _) = app(Arc::clone(&query));
    let response = app
        .oneshot(Request::builder().uri(PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(query.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn endpoint_does_not_mount_health_or_cors() {
    let query = Arc::new(Query::new(QueryOutcome::Available));
    let (app, authorization) = app(query);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

#[tokio::test]
async fn unavailable_query_returns_static_no_store_response() {
    let query = Arc::new(Query::new(QueryOutcome::Unavailable));
    let (app, authorization) = app(Arc::clone(&query));
    let response = request(app, &authorization, "GET", Body::empty()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_store(&response);
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(query.calls.load(Ordering::SeqCst), 1);
}
