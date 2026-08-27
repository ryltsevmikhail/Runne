use super::*;

#[test]
fn legacy_mutations_reject_before_input_identity_or_native_store() {
    for command in [
        ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
        ProviderCredentialCommand::Delete(ProviderCredentialId::OpenAi),
    ] {
        let result = execute_provider_credential_on_platform(
            command,
            &mut PanicRead,
            false,
            &mut PanicBackend,
            &PanicResolver,
            true,
        );
        assert!(matches!(
            result,
            Err(CliError::UnsupportedCredentialBackend)
        ));
    }
}

struct PanicRead;

impl std::io::Read for PanicRead {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("legacy mutation must not read stdin")
    }
}

struct PanicResolver;

impl CredentialIdentityResolver for PanicResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        panic!("legacy mutation must not resolve native identity")
    }
}

struct PanicBackend;

impl CredentialBackend for PanicBackend {
    fn status(
        &self,
        _: ProviderCredentialId,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        panic!("legacy mutation must not query native store")
    }
}
