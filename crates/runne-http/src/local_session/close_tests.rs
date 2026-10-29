use super::*;

#[tokio::test]
async fn close_requires_exactly_one_valid_session_authority() {
    for values in [
        vec![],
        vec!["Bearer deadbeef".to_owned()],
        vec![format!(
            "GocodeSession {}",
            URL_SAFE_NO_PAD.encode([0x44; 32])
        )],
        vec![
            "GocodeSession abc=".to_owned(),
            "GocodeSession abc=".to_owned(),
        ],
    ] {
        let (state, _directory) = state();
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/local-session/close");
        for value in values {
            request = request.header("authorization", value);
        }
        let response = local_session_router(state)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
