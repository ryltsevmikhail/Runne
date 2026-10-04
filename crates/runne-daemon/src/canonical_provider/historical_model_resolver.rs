use runne_application::provider::{
    HistoricalProviderModelError, HistoricalProviderModelResolver,
    HistoricalProviderProfileIdentity,
};
use runne_provider::ModelRef;

/// Resolves only fixed profiles shipped with this binary.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CompiledHistoricalProviderModelResolver;

impl HistoricalProviderModelResolver for CompiledHistoricalProviderModelResolver {
    fn resolve_exact(
        &self,
        identity: &HistoricalProviderProfileIdentity,
    ) -> Result<ModelRef, HistoricalProviderModelError> {
        let providers = [
            fixed_profile(
                "openai",
                runne_provider_openai::OPENAI_RESPONSES_PROFILE_ID,
                include_bytes!("../../../../docs/profiles/openai-responses-text-v1.json"),
                ProviderProfile::OpenAi,
            ),
            fixed_profile(
                "openai-background",
                runne_provider_openai::OPENAI_RESPONSES_BACKGROUND_PROFILE_ID,
                include_bytes!(
                    "../../../../docs/profiles/openai-responses-background-text-v1.json"
                ),
                ProviderProfile::OpenAi,
            ),
            fixed_profile(
                "deepseek",
                runne_provider_deepseek::DEEPSEEK_RESPONSES_PROFILE_ID,
                include_bytes!("../../../../docs/profiles/deepseek-responses-text-v1.json"),
                ProviderProfile::DeepSeek,
            ),
        ];
        for profile in providers.into_iter().flatten() {
            if profile.provider != identity.provider_id().as_str()
                || profile.id != identity.profile_id()
                || profile.digest != *identity.profile_digest()
            {
                continue;
            }
            return ModelRef::new(
                identity.provider_id().clone(),
                profile.model,
                profile.revision,
            )
            .map_err(|_| HistoricalProviderModelError::ProfileUnavailable);
        }
        for profile in [zai_profile(), qwen_profile()] {
            if profile.provider == identity.provider_id().as_str()
                && profile.id == identity.profile_id()
                && profile.digest == *identity.profile_digest()
            {
                return ModelRef::new(
                    identity.provider_id().clone(),
                    profile.model,
                    profile.revision,
                )
                .map_err(|_| HistoricalProviderModelError::ProfileUnavailable);
            }
        }
        Err(HistoricalProviderModelError::ProfileUnavailable)
    }
}

#[derive(Clone, Copy)]
enum ProviderProfile {
    OpenAi,
    DeepSeek,
}

struct PinnedProfile {
    provider: &'static str,
    id: &'static str,
    digest: [u8; 32],
    model: String,
    revision: String,
}

fn fixed_profile(
    provider: &'static str,
    expected_id: &'static str,
    bytes: &[u8],
    kind: ProviderProfile,
) -> Option<PinnedProfile> {
    match kind {
        ProviderProfile::OpenAi => {
            let profile =
                runne_provider_openai::OpenAiResponsesTextProfile::from_json(bytes).ok()?;
            (profile.profile_id() == expected_id).then(|| PinnedProfile {
                provider,
                id: expected_id,
                digest: profile.profile_digest(),
                model: profile.model_id().to_owned(),
                revision: profile.model_revision().to_owned(),
            })
        }
        ProviderProfile::DeepSeek => {
            let profile =
                runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(bytes).ok()?;
            (profile.profile_id() == expected_id).then(|| PinnedProfile {
                provider,
                id: expected_id,
                digest: profile.profile_digest(),
                model: profile.model_id().to_owned(),
                revision: profile.model_revision().to_owned(),
            })
        }
    }
}

fn zai_profile() -> PinnedProfile {
    let profile = runne_provider_zai::profile();
    PinnedProfile {
        provider: runne_provider_zai::ZAI_PROVIDER_ID,
        id: runne_provider_zai::ZAI_PROFILE_ID,
        digest: profile.profile_digest(),
        model: runne_provider_zai::ZAI_MODEL_ID.to_owned(),
        revision: runne_provider_zai::ZAI_MODEL_REVISION.to_owned(),
    }
}

fn qwen_profile() -> PinnedProfile {
    let profile = runne_provider_qwencloud::profile();
    PinnedProfile {
        provider: runne_provider_qwencloud::QWENCLOUD_PROVIDER_ID,
        id: runne_provider_qwencloud::QWENCLOUD_PROFILE_ID,
        digest: profile.profile_digest(),
        model: runne_provider_qwencloud::QWENCLOUD_MODEL_ID.to_owned(),
        revision: runne_provider_qwencloud::QWENCLOUD_MODEL_REVISION.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider::ProviderId;

    #[test]
    fn exact_compiled_profile_resolves_historic_model_independent_of_default() {
        let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
            "../../../../docs/profiles/openai-responses-text-v1.json"
        ))
        .unwrap();
        let identity = HistoricalProviderProfileIdentity::new(
            ProviderId::new("openai".to_owned()).unwrap(),
            profile.profile_id().to_owned(),
            profile.profile_digest(),
        )
        .unwrap();

        let model = CompiledHistoricalProviderModelResolver
            .resolve_exact(&identity)
            .unwrap();
        assert_eq!(model.model_id(), runne_provider_openai::OPENAI_MODEL_ID);
        assert_eq!(
            model.revision(),
            runne_provider_openai::OPENAI_MODEL_REVISION
        );
    }

    #[test]
    fn changed_digest_or_profile_does_not_fall_back_to_current_profile() {
        let identity = HistoricalProviderProfileIdentity::new(
            ProviderId::new("openai".to_owned()).unwrap(),
            runne_provider_openai::OPENAI_RESPONSES_PROFILE_ID.to_owned(),
            [0x51; 32],
        )
        .unwrap();
        assert_eq!(
            CompiledHistoricalProviderModelResolver.resolve_exact(&identity),
            Err(HistoricalProviderModelError::ProfileUnavailable)
        );
    }

    #[test]
    fn background_profile_resolves_only_in_its_separate_credential_realm() {
        let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
            "../../../../docs/profiles/openai-responses-background-text-v1.json"
        ))
        .unwrap();
        let identity = HistoricalProviderProfileIdentity::new(
            ProviderId::new("openai-background".to_owned()).unwrap(),
            profile.profile_id().to_owned(),
            profile.profile_digest(),
        )
        .unwrap();
        let model = CompiledHistoricalProviderModelResolver
            .resolve_exact(&identity)
            .unwrap();
        assert_eq!(model.provider_id().as_str(), "openai-background");
        assert_eq!(model.model_id(), "gpt-5.5");
        assert_eq!(model.revision(), "2026-04-23");

        let wrong_realm = HistoricalProviderProfileIdentity::new(
            ProviderId::new("openai".to_owned()).unwrap(),
            profile.profile_id().to_owned(),
            profile.profile_digest(),
        )
        .unwrap();
        assert_eq!(
            CompiledHistoricalProviderModelResolver.resolve_exact(&wrong_realm),
            Err(HistoricalProviderModelError::ProfileUnavailable)
        );
    }

    #[test]
    fn supported_legacy_singleton_profiles_resolve_their_own_model_refs() {
        let deepseek = runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(
            include_bytes!("../../../../docs/profiles/deepseek-responses-text-v1.json"),
        )
        .unwrap();
        let deepseek_identity = HistoricalProviderProfileIdentity::new(
            ProviderId::new("deepseek".to_owned()).unwrap(),
            deepseek.profile_id().to_owned(),
            deepseek.profile_digest(),
        )
        .unwrap();
        let deepseek_model = CompiledHistoricalProviderModelResolver
            .resolve_exact(&deepseek_identity)
            .unwrap();
        assert_eq!(
            deepseek_model.model_id(),
            runne_provider_deepseek::DEEPSEEK_MODEL_ID
        );

        for (provider, profile_id, digest, model, revision) in [
            (
                runne_provider_zai::ZAI_PROVIDER_ID,
                runne_provider_zai::ZAI_PROFILE_ID,
                runne_provider_zai::profile().profile_digest(),
                runne_provider_zai::ZAI_MODEL_ID,
                runne_provider_zai::ZAI_MODEL_REVISION,
            ),
            (
                runne_provider_qwencloud::QWENCLOUD_PROVIDER_ID,
                runne_provider_qwencloud::QWENCLOUD_PROFILE_ID,
                runne_provider_qwencloud::profile().profile_digest(),
                runne_provider_qwencloud::QWENCLOUD_MODEL_ID,
                runne_provider_qwencloud::QWENCLOUD_MODEL_REVISION,
            ),
        ] {
            let identity = HistoricalProviderProfileIdentity::new(
                ProviderId::new(provider.to_owned()).unwrap(),
                profile_id.to_owned(),
                digest,
            )
            .unwrap();
            let resolved = CompiledHistoricalProviderModelResolver
                .resolve_exact(&identity)
                .unwrap();
            assert_eq!(resolved.model_id(), model);
            assert_eq!(resolved.revision(), revision);
        }
    }
}
