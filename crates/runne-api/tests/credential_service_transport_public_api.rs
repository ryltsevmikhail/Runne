use runne_api::{
    AcceptedCredentialServiceRegistration, CredentialServiceRegistrationInstall,
    CredentialServiceRuntimeEnvelope, VerifiedCredentialServiceRuntimePayload,
};

#[test]
fn credential_service_transport_is_visible_from_the_crate_root() {
    macro_rules! visible {
        ($($ty:ty),+ $(,)?) => { $(let _ = std::any::type_name::<$ty>();)+ };
    }
    visible!(
        AcceptedCredentialServiceRegistration,
        CredentialServiceRegistrationInstall,
        CredentialServiceRuntimeEnvelope,
        VerifiedCredentialServiceRuntimePayload,
    );
}
