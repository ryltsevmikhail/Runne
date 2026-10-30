use super::*;
impl DaemonCanonicalProviderService {
    /// Read-only discovery; admission rechecks this grant on every dispatch.
    pub(crate) fn available_coding_profile(&self) -> Option<(String, [u8; 32])> {
        #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
        {
            let profile = self.tool_profile.as_ref()?;
            if profile.profile_id() != runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID
                || self.tool_adapter.is_none()
            {
                return None;
            }
            let grant = self.tool_profile_grant.as_ref()?;
            let (tokens, cost) = self
                .execution_store
                .secondary_profile_utilization(&self.launch_capability, grant)
                .ok()?;
            if tokens.remaining == 0 || cost.remaining == 0 {
                return None;
            }
            Some((profile.profile_id().to_owned(), profile.profile_digest()))
        }
        #[cfg(not(all(feature = "desktop-protected", target_os = "linux")))]
        {
            None
        }
    }
}
