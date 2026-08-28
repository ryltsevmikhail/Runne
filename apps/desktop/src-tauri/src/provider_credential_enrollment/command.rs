use runne_api::{
    ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2,
    ProviderCredentialVerificationKindV2,
};
use serde::Deserialize;

/// Renderer input. There is intentionally no credential or native intent ID.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialIntentIpc {
    pub(crate) provider: ProviderCredentialProviderV2,
    pub(crate) action: ProviderCredentialEnrollmentActionV2,
    pub(crate) expected_revision: u64,
    pub(crate) verification_kind: Option<ProviderCredentialVerificationKindV2>,
}

impl CredentialIntentIpc {
    pub(crate) fn valid(self) -> bool {
        self.expected_revision != 0
            && !(matches!(
                self.action,
                ProviderCredentialEnrollmentActionV2::Pair
                    | ProviderCredentialEnrollmentActionV2::MigrateLegacy
            ) && self.verification_kind.is_some())
            && !(self.action == ProviderCredentialEnrollmentActionV2::Revoke
                && self.verification_kind.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ipc_recursively_rejects_credential_and_renderer_native_intent_id() {
        for value in [
            json!({"provider":"openai","action":"pair","expectedRevision":7,"credential":"secret"}),
            json!({"provider":"openai","action":"pair","expectedRevision":7,"nativeIntentId":"forged"}),
        ] {
            assert!(serde_json::from_value::<CredentialIntentIpc>(value).is_err());
        }
    }
}
