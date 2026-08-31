use runne_api::{
    ApiActor, ApiPrincipalId, BeginProviderCredentialEnrollment, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    CredentialFence, CredentialLifecycleRevision, CredentialLifecycleSnapshot,
    CredentialReadinessRevision, ProviderId,
};

pub(crate) fn lifecycle_snapshot() -> CredentialLifecycleSnapshot {
    CredentialLifecycleSnapshot::new(
        ProviderId::new("openai").unwrap(),
        None,
        CredentialLifecycleRevision::new(7).unwrap(),
        CredentialFence::new(4).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        9,
    )
    .unwrap()
}

pub(crate) fn begin(
    action: ProviderCredentialEnrollmentActionV2,
) -> BeginProviderCredentialEnrollment {
    BeginProviderCredentialEnrollment::new(
        action,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
        "intent-a",
    )
    .unwrap()
}

pub(crate) fn context() -> ProviderCredentialCommandContext {
    ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes([1; 16]),
        idempotency_key: IdempotencyKey::new("context-a").unwrap(),
        principal: ApiPrincipalId::new("principal-a").unwrap(),
        actor: ApiActor::new("actor-a").unwrap(),
    }
}
