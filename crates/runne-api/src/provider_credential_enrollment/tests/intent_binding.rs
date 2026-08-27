use crate::{
    ApiActor, ApiPrincipalId, ProviderCredentialCommandContext, ProviderCredentialProviderV2,
    ProviderCredentialVerificationKindV2, ProviderCredentialVerifyIntentBinding,
    VerifyProviderCredential,
};
use runne_domain::id::{CommandId, IdempotencyKey};

fn context() -> ProviderCredentialCommandContext {
    ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes([7; 16]),
        idempotency_key: IdempotencyKey::new("verify-binding").unwrap(),
        principal: ApiPrincipalId::new("principal-a").unwrap(),
        actor: ApiActor::new("actor-a").unwrap(),
    }
}

fn command(
    provider: ProviderCredentialProviderV2,
    revision: u64,
    kind: ProviderCredentialVerificationKindV2,
) -> VerifyProviderCredential {
    VerifyProviderCredential::new(
        provider,
        revision,
        kind,
        "018f8d23-7f90-7c00-8000-000000000001",
        "native-intent",
    )
    .unwrap()
}

#[test]
fn verify_intent_binding_changes_for_provider_revision_and_kind() {
    let context = context();
    let baseline = ProviderCredentialVerifyIntentBinding::new(
        &command(
            ProviderCredentialProviderV2::OpenAi,
            2,
            ProviderCredentialVerificationKindV2::Local,
        ),
        &context,
    );
    for substituted in [
        command(
            ProviderCredentialProviderV2::DeepSeek,
            2,
            ProviderCredentialVerificationKindV2::Local,
        ),
        command(
            ProviderCredentialProviderV2::OpenAi,
            3,
            ProviderCredentialVerificationKindV2::Local,
        ),
        command(
            ProviderCredentialProviderV2::OpenAi,
            2,
            ProviderCredentialVerificationKindV2::Remote,
        ),
    ] {
        assert_ne!(
            baseline.action_provider_revision_digest(),
            ProviderCredentialVerifyIntentBinding::new(&substituted, &context)
                .action_provider_revision_digest()
        );
    }
}

#[test]
fn verify_intent_binding_changes_for_command_identity_and_context() {
    let baseline_context = context();
    let baseline_command = command(
        ProviderCredentialProviderV2::OpenAi,
        2,
        ProviderCredentialVerificationKindV2::Local,
    );
    let changed_command = VerifyProviderCredential::new(
        ProviderCredentialProviderV2::OpenAi,
        2,
        ProviderCredentialVerificationKindV2::Local,
        "018f8d23-7f90-7c00-8000-000000000002",
        "native-intent",
    )
    .unwrap();
    let changed_context = ProviderCredentialCommandContext {
        idempotency_key: IdempotencyKey::new("another-verify-binding").unwrap(),
        ..context()
    };
    let baseline = ProviderCredentialVerifyIntentBinding::new(&baseline_command, &baseline_context);

    assert_ne!(
        baseline.command_identity_digest(),
        ProviderCredentialVerifyIntentBinding::new(&changed_command, &baseline_context)
            .command_identity_digest()
    );
    assert_ne!(
        baseline.command_identity_digest(),
        ProviderCredentialVerifyIntentBinding::new(&baseline_command, &changed_context)
            .command_identity_digest()
    );
}
