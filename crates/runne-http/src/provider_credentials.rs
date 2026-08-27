//! Closed compatibility routes for removed V1 credential mutation.

use axum::{Router, extract::Extension, http::StatusCode, response::Response, routing::put};

use crate::error::{RequestId, canonical_error_response};

const V1_UNSUPPORTED_CODE: &str = "provider_credential_control_v1_unsupported";

/// Mounts V1 paths only to return a fixed post-authentication rejection.
///
/// The handler has no path, header, state, or body extractor. In particular,
/// it cannot deserialize or consume credential material from the request body.
pub fn provider_credential_router() -> Router {
    Router::new().route(
        "/v1/providers/{provider}/credential",
        put(v1_unsupported).delete(v1_unsupported),
    )
}

async fn v1_unsupported(Extension(request_id): Extension<RequestId>) -> Response {
    canonical_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        V1_UNSUPPORTED_CODE,
        &request_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use futures::{future, stream};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn provider_credential_v1_is_closed_without_polling_accepted_body_shapes() {
        for (shape, bytes, headers) in [
            ("empty", b"".as_slice(), &[][..]),
            ("malformed_json", b"{not-json".as_slice(), &[][..]),
            (
                "oversized",
                b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".as_slice(),
                &[("content-length", "8192")][..],
            ),
            (
                "chunked",
                b"credential=must-not-be-read".as_slice(),
                &[("transfer-encoding", "chunked")][..],
            ),
            (
                "compressed",
                b"not-a-gzip-stream".as_slice(),
                &[("content-encoding", "gzip")][..],
            ),
            (
                "expect_continue",
                b"credential=must-not-be-read".as_slice(),
                &[("expect", "100-continue")][..],
            ),
        ] {
            for method in ["PUT", "DELETE"] {
                let polls = Arc::new(AtomicUsize::new(0));
                let mut builder = Request::builder()
                    .method(method)
                    .uri("/v1/providers/not-a-provider/credential");
                for (name, value) in headers {
                    builder = builder.header(*name, *value);
                }
                let mut request = builder
                    .body(counted_body(bytes, Arc::clone(&polls)))
                    .expect("request");
                request.extensions_mut().insert(RequestId::generate());
                let response = provider_credential_router()
                    .oneshot(request)
                    .await
                    .expect("response");
                assert_eq!(
                    response.status(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "{shape} {method}"
                );
                assert_eq!(polls.load(Ordering::SeqCst), 0, "{shape} {method}");
                let body = axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .expect("error body");
                assert!(
                    std::str::from_utf8(&body)
                        .expect("utf8")
                        .contains(V1_UNSUPPORTED_CODE)
                );
            }
        }

        for method in ["PUT", "DELETE"] {
            let polls = Arc::new(AtomicUsize::new(0));
            let mut request = Request::builder()
                .method(method)
                .uri("/v1/providers/not-a-provider/credential")
                .body(slow_counted_body(Arc::clone(&polls)))
                .expect("request");
            request.extensions_mut().insert(RequestId::generate());
            let response = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                provider_credential_router().oneshot(request),
            )
            .await
            .expect("slow body must not delay rejection")
            .expect("response");
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "slow {method}"
            );
            assert_eq!(polls.load(Ordering::SeqCst), 0, "slow {method}");
        }
    }

    fn counted_body(bytes: &[u8], polls: Arc<AtomicUsize>) -> Body {
        let bytes = axum::body::Bytes::copy_from_slice(bytes);
        Body::from_stream(stream::once(async move {
            polls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(bytes)
        }))
    }

    fn slow_counted_body(polls: Arc<AtomicUsize>) -> Body {
        Body::from_stream(stream::once(async move {
            polls.fetch_add(1, Ordering::SeqCst);
            future::pending::<Result<axum::body::Bytes, std::convert::Infallible>>().await
        }))
    }
}
