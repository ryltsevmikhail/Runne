fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}

fn request_binding(
    session_id: [u8; 16],
    daemon_instance_id: [u8; 16],
    supervisor_generation: u64,
    request_id: [u8; 16],
) -> ProtectedCredentialEnrollmentRequestBinding {
    let (action_provider_revision, command_identity) = credential_claims(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
    );
    ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        session_id,
        daemon_instance_id,
        3,
        supervisor_generation,
        request_id,
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        action_provider_revision,
        command_identity,
        100,
        200,
    )
    .unwrap()
}

fn request_binding_with(
    release: [u8; 32],
    supervisor: u64,
    peer: [u8; 32],
    confirmation: [u8; 32],
    broker: [u8; 32],
    issued: u64,
    expiry: u64,
) -> ProtectedCredentialEnrollmentRequestBinding {
    let (action_provider_revision, command_identity) = credential_claims(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
    );
    request_binding_with_claims(
        release,
        supervisor,
        peer,
        confirmation,
        broker,
        action_provider_revision,
        command_identity,
        issued,
        expiry,
    )
}

#[allow(clippy::too_many_arguments)]
fn request_binding_with_claims(
    release: [u8; 32],
    supervisor: u64,
    peer: [u8; 32],
    confirmation: [u8; 32],
    broker: [u8; 32],
    action_provider_revision: [u8; 32],
    command_identity: [u8; 32],
    issued: u64,
    expiry: u64,
) -> ProtectedCredentialEnrollmentRequestBinding {
    ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        uuid(2),
        uuid(3),
        3,
        supervisor,
        uuid(4),
        release,
        peer,
        confirmation,
        broker,
        action_provider_revision,
        command_identity,
        issued,
        expiry,
    )
    .unwrap()
}

fn credential_claims(
    action: ProviderCredentialEnrollmentActionV2,
    provider: ProviderCredentialProviderV2,
    revision: u64,
    command_identity: &str,
    idempotency_key: &str,
) -> ([u8; 32], [u8; 32]) {
    let command = BeginProviderCredentialEnrollment::new(
        action,
        provider,
        revision,
        command_identity,
        idempotency_key,
        "native-intent-a",
    )
    .unwrap();
    let context = ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes([1; 16]),
        idempotency_key: IdempotencyKey::new("context-idempotency").unwrap(),
        principal: ApiPrincipalId::new("principal-a").unwrap(),
        actor: ApiActor::new("actor-a").unwrap(),
    };
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    (
        *binding.action_provider_revision_digest(),
        *binding.command_identity_digest(),
    )
}

fn admission_binding() -> ProtectedCredentialEnrollmentAdmissionBinding {
    admission_binding_with([4; 32], 2, [5; 32], [6; 32], [7; 32], 200)
}

fn admission_binding_with(
    release: [u8; 32],
    supervisor: u64,
    peer: [u8; 32],
    confirmation: [u8; 32],
    broker: [u8; 32],
    expiry: u64,
) -> ProtectedCredentialEnrollmentAdmissionBinding {
    ProtectedCredentialEnrollmentAdmissionBinding::new(
        [8; 32],
        release,
        [9; 32],
        supervisor,
        [10; 32],
        4,
        peer,
        confirmation,
        broker,
        uuid(5),
        expiry,
    )
    .unwrap()
}

fn authenticator(byte: u8) -> ProtectedCredentialEnrollmentAuthenticator {
    let keys = LaunchSecret::from_bytes([byte; 32]).unwrap().derive_keys();
    ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys)
}

fn request_frame(
    authenticator: &ProtectedCredentialEnrollmentAuthenticator,
) -> (ProtectedCredentialEnrollmentRequestBinding, Vec<u8>) {
    let binding = request_binding(uuid(2), uuid(3), 2, uuid(4));
    let request = authenticator.issue_request(binding.clone(), 1).unwrap();
    (
        binding,
        ProtectedCredentialEnrollmentControlFrame::Request(request).encode_frame(),
    )
}
