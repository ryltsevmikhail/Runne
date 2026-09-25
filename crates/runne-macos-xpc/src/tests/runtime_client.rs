#[test]
fn runtime_client_uses_the_qualification_port_without_a_new_endpoint() {
    let source = include_str!("../client.rs");
    assert!(source.contains("role_client!(CredentialServiceRuntimeXpcClient, Runtime);"));
    assert!(
        source.contains(
            "impl CredentialServiceQualificationPort for CredentialServiceRuntimeXpcClient"
        )
    );
    assert!(source.contains("CredentialServicePortError::Unsupported"));
    assert!(
        !source.contains(
            "exchange_method!(self, request, context, CredentialServiceQualificationReply)"
        )
    );
    assert!(!source.contains("CredentialServiceQualificationXpcClient"));
    assert!(!source.contains("CredentialServiceEndpointRole::Qualification"));
}
