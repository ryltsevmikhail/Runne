use super::*;
use runne_provider_deepseek::{DeepSeekResponsesTextProfile, DeepSeekResponsesToolProfile};

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(super) fn opt_in_tool_profile(
    text_profile: &SharedTextProviderProfile,
) -> Option<Arc<SharedTextProviderProfile>> {
    let profile = exact_tool_profile().ok()?;
    let text = profile.text_profile();
    if text_profile.profile_id() != text.profile_id()
        || text_profile.profile_digest() != text.profile_digest()
    {
        return None;
    }
    Some(Arc::new(SharedTextProviderProfile::new(Arc::new(profile))))
}

pub(super) fn exact_tool_profile()
-> Result<DeepSeekResponsesToolProfile, runne_provider_deepseek::DeepSeekProfileError> {
    DeepSeekResponsesToolProfile::new(DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))?)
}

#[cfg(all(test, feature = "desktop-protected", target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn deepseek_tool_selection_requires_exact_primary_and_keeps_text_identity() {
        let tool = exact_tool_profile().unwrap();
        let text = tool.text_profile().clone();
        let shared = SharedTextProviderProfile::new(Arc::new(text.clone()));
        let selected = opt_in_tool_profile(&shared).unwrap();
        assert_eq!(
            selected.profile_id(),
            runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID
        );
        assert_ne!(selected.profile_digest(), text.profile_digest());
        assert_eq!(
            selected.pricing_revision_digest(),
            text.pricing_revision_digest()
        );
        assert!(opt_in_tool_profile(selected.as_ref()).is_none());
        assert!(super::super::openai_profile::opt_in_tool_profile(&shared).is_none());
    }
}

impl DaemonCanonicalProviderService {
    pub(crate) fn coding_agent_tools_enabled(&self) -> bool {
        self.tool_profile.as_ref().is_some_and(|p| {
            p.profile_id() == runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID
        })
    }
}

impl DaemonCanonicalProviderService {
    pub(crate) fn validate_tool_preview(&self, bytes: &[u8]) -> Result<(), ()> {
        if matches!(
            self.prohibited_content.inspect(
                runne_application::prohibited_content::CanonicalContentBoundary::CanonicalMutation,
                bytes
            ),
            Ok(runne_application::prohibited_content::ContentDisposition::Allowed { .. })
        ) {
            Ok(())
        } else {
            Err(())
        }
    }
}
