use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use gocode_runtime_client::{
    MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1, RecoveryObservationStatusV1, RuntimeApiErrorKind,
    mock_authenticated_runtime_client,
};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

use crate::support::*;

#[tokio::test]
async fn telemetry_uses_authenticated_exact_get_path_and_public_status_type() {
    let (client, request) = client_for(response(200, &[], valid_snapshot(1)), true, 1).await;
    assert_eq!(
        client
            .operational_telemetry()
            .await
            .expect("valid telemetry")
            .schema_version(),
        1
    );
    let request = request.await.expect("fixture task");
    assert_eq!(request.path, "/v1/runtime/operational-telemetry");
    assert!(request.authorization.starts_with("GocodeSession "));
    let _: RecoveryObservationStatusV1 = RecoveryObservationStatusV1::Unavailable;
}

#[tokio::test]
async fn telemetry_missing_capability_accepts_zero_connections() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fixture listener");
    let client = mock_authenticated_runtime_client(
        &format!("http://{}", listener.local_addr().expect("address")),
        session(false, 1),
    )
    .expect("client");
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = Arc::clone(&accepted);
    let (tx, mut receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        if listener.accept().await.is_ok() {
            accepted_task.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(());
        }
    });
    assert_eq!(
        telemetry_error(client.operational_telemetry().await).kind(),
        RuntimeApiErrorKind::InvalidResponse
    );
    assert!(
        timeout(Duration::from_millis(100), &mut receiver)
            .await
            .is_err(),
        "client must not connect"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn telemetry_maps_status_before_held_body_is_released() {
    for (status, expected) in [
        (401, RuntimeApiErrorKind::Unauthorized),
        (503, RuntimeApiErrorKind::Unavailable),
        (500, RuntimeApiErrorKind::InvalidResponse),
    ] {
        let (client, request, release, server) = held_status_client(status).await;
        let result = timeout(Duration::from_secs(1), client.operational_telemetry())
            .await
            .expect("status must not wait for body");
        assert_static_error(&telemetry_error(result), expected);
        let request = request.await.expect("fixture request");
        assert_eq!(request.path, "/v1/runtime/operational-telemetry");
        release.send(()).expect("release body");
        server.await.expect("fixture task");
    }
}

#[tokio::test]
async fn telemetry_requires_exact_headers_and_bounded_content_length() {
    let oversized = padded_snapshot(1, MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1 + 1);
    let cases = [
        raw_response(
            200,
            &[
                "content-type: application/json; charset=utf-8",
                "cache-control: no-store",
            ],
            valid_snapshot(1),
        ),
        raw_response(
            200,
            &[
                "content-type: application/json",
                "cache-control: private, no-store",
            ],
            valid_snapshot(1),
        ),
        raw_response(200, &["content-type: application/json"], valid_snapshot(1)),
        raw_response(
            200,
            &[
                "content-type: application/json",
                "cache-control: no-store",
                "content-length: invalid",
            ],
            valid_snapshot(1),
        ),
        raw_response(
            200,
            &[
                "content-type: application/json",
                "cache-control: no-store",
                "content-length: 1",
                "content-length: 1",
            ],
            " ",
        ),
        raw_response(
            200,
            &[
                "content-type: application/json",
                "cache-control: no-store",
                "content-length: 65537",
            ],
            oversized,
        ),
    ];
    for wire in cases {
        let (client, request) = client_for(wire, true, 1).await;
        assert_static_error(
            &telemetry_error(client.operational_telemetry().await),
            RuntimeApiErrorKind::InvalidResponse,
        );
        request.await.expect("fixture task");
    }
}

#[tokio::test]
async fn telemetry_accepts_fragmented_exact_limit_and_rejects_cumulative_overflow() {
    let exact = padded_snapshot(1, MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1);
    let (client, request) = client_for(
        chunked_response(&[&exact.as_bytes()[..40_000], &exact.as_bytes()[40_000..]]),
        true,
        1,
    )
    .await;
    assert_eq!(
        client
            .operational_telemetry()
            .await
            .expect("exact limit")
            .schema_version(),
        1
    );
    request.await.expect("fixture task");
    let overflow = padded_snapshot(1, MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1 + 1);
    let (client, request) = client_for(
        chunked_response(&[
            &overflow.as_bytes()[..40_000],
            &overflow.as_bytes()[40_000..],
        ]),
        true,
        1,
    )
    .await;
    assert_static_error(
        &telemetry_error(client.operational_telemetry().await),
        RuntimeApiErrorKind::InvalidResponse,
    );
    request.await.expect("fixture task");
}

#[tokio::test]
async fn telemetry_rejects_any_access_control_response_header_before_body_parse() {
    for name in [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-credentials",
        "access-control-expose-headers",
        "access-control-max-age",
    ] {
        let marker = "task12-cors-header-marker";
        let headers = [
            "content-type: application/json".to_owned(),
            "cache-control: no-store".to_owned(),
            format!("{name}: {marker}"),
        ];
        let wire = raw_response(
            200,
            &headers.iter().map(String::as_str).collect::<Vec<_>>(),
            valid_snapshot(1),
        );
        let (client, request) = client_for(wire, true, 1).await;
        let error = telemetry_error(client.operational_telemetry().await);
        assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
        assert!(!format!("{error:?}").contains(marker));
        assert!(!error.to_string().contains(marker));
        request.await.expect("fixture request");
    }
}
