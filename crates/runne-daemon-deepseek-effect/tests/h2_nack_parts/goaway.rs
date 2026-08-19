#[tokio::test]
async fn goaway_no_error_is_uncertain_after_one_durable_effect() {
    assert_uncertain_single_effect(Nack::GoawayNoError).await;
}
