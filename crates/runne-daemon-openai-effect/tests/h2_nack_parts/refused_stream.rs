#[tokio::test]
async fn refused_stream_is_uncertain_after_one_durable_effect() {
    assert_uncertain_single_effect(Nack::RefusedStream).await;
}
