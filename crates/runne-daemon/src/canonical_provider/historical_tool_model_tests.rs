use super::*;
use runne_provider::ProviderId;

#[test]
fn historical_coding_profile_requires_exact_id_digest_and_provider() {
    let tool = super::super::deepseek_profile::exact_tool_profile().unwrap();
    let identity = HistoricalProviderProfileIdentity::new(
        ProviderId::new("deepseek").unwrap(),
        runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID.to_owned(),
        tool.profile_digest(),
    )
    .unwrap();
    let model = CompiledHistoricalProviderModelResolver
        .resolve_exact(&identity)
        .unwrap();
    assert_eq!(model.model_id(), tool.text_profile().model_id());
    assert_eq!(model.revision(), tool.text_profile().model_revision());
    let mut wrong = tool.profile_digest();
    wrong[0] ^= 1;
    for (provider, id, digest) in [
        (
            "deepseek",
            runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID,
            wrong,
        ),
        (
            "different",
            runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID,
            tool.profile_digest(),
        ),
        (
            "deepseek",
            runne_provider_deepseek::DEEPSEEK_RESPONSES_PROFILE_ID,
            tool.profile_digest(),
        ),
    ] {
        let identity = HistoricalProviderProfileIdentity::new(
            ProviderId::new(provider).unwrap(),
            id.to_owned(),
            digest,
        )
        .unwrap();
        assert!(
            CompiledHistoricalProviderModelResolver
                .resolve_exact(&identity)
                .is_err()
        );
    }
}
