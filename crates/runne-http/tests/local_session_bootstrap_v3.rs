mod error {
    pub use runne_http::error::*;
}

#[path = "../src/local_session.rs"]
mod local_session;

#[tokio::test]
async fn oversized_transport_body_has_canonical_rejection() {
    local_session::tests::assert_oversized_transport_body_has_canonical_rejection().await;
}

#[tokio::test]
async fn verified_tls_router_issues_and_consumes_a_challenge() {
    local_session::tests::assert_verified_tls_router_issues_and_consumes_a_challenge().await;
}
