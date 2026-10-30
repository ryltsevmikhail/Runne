use super::*;

#[test]
fn mutations_reject_before_identity_or_native_store_when_the_backend_is_unsupported() {
    for command in [
        ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
        ProviderCredentialCommand::Delete(ProviderCredentialId::OpenAi),
    ] {
        let result = execute_provider_credential_on_platform(
            command,
            &PanicBackend,
            &PanicResolver,
            false,
            &panic_read,
        );
        assert!(matches!(
            result,
            Err(CliError::UnsupportedCredentialBackend)
        ));
    }
}

fn panic_read(_: ProviderCredentialId) -> Result<ProviderCredentialMaterial, CliError> {
    panic!("mutation must not read a secret")
}

struct PanicResolver;

impl CredentialIdentityResolver for PanicResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        panic!("mutation must not resolve native identity")
    }
}

struct PanicBackend;

impl CredentialBackend for PanicBackend {
    fn status(
        &self,
        _: ProviderCredentialId,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        panic!("mutation must not query native store")
    }

    fn store(
        &self,
        _: ProviderCredentialId,
        _: &ProviderCredentialMaterial,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        panic!("mutation must not store")
    }

    fn delete(&self, _: ProviderCredentialId) -> Result<(), SecureStoreError> {
        panic!("mutation must not delete")
    }
}
