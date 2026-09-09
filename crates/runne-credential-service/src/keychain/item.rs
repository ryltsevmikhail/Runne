use runne_provider::CredentialVersionRef;

pub const KEYCHAIN_ACCESS_GROUP: &str = "758F9Z45SR.com.runne.credential-service";
const SERVICE_PREFIX: &str = "dev.runne.provider-credential.v1.version";

/// Complete non-secret locator for one immutable provider credential version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialItemLocator {
    service: String,
    account: String,
}

impl CredentialItemLocator {
    pub(crate) fn new(reference: &CredentialVersionRef) -> Self {
        Self {
            service: format!(
                "{SERVICE_PREFIX}.{}.{}",
                reference.version(),
                hex::encode(reference.ref_digest())
            ),
            account: reference.provider().as_str().to_owned(),
        }
    }

    pub(crate) fn service(&self) -> &str {
        &self.service
    }

    pub(crate) fn account(&self) -> &str {
        &self.account
    }

    pub const fn access_group() -> &'static str {
        KEYCHAIN_ACCESS_GROUP
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn with_account_for_test(reference: &CredentialVersionRef, account: &str) -> Self {
        let mut locator = Self::new(reference);
        account.clone_into(&mut locator.account);
        locator
    }
}
