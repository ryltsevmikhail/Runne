use std::sync::Arc;

use runne_http::ProviderCredentialEnrollmentHttpAdmissionResolver;

use super::*;
use crate::application::provider_credential_enrollment::http_admission_resolver::DaemonCredentialHttpAdmissionResolver;

#[test]
fn daemon_resolver_releases_one_exact_registered_control_exchange() {
    let command = begin_command();
    let bindings = begin_bindings();
    let expected = DaemonCredentialHttpAdmissionExpectation::new(
        uuid(2),
        [11; 32],
        bindings.0,
        bindings.1,
        native_intent("intent-a"),
        1,
        2,
        [7; 32],
        120_000,
    )
    .unwrap();
    let (exchange, request, admission) = fixture_with_bindings(expected, bindings);
    let registered = exchange
        .register(request, admission, context(), 110_000)
        .unwrap();
    let resolver = DaemonCredentialHttpAdmissionResolver::new(registered, Arc::new(|| 110_000));

    assert!(resolver.resolve_begin(uuid(2), &command).is_ok());
    assert!(resolver.resolve_begin(uuid(2), &command).is_err());
}
