use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use zeroize::Zeroizing;

use super::*;
use crate::peer_requirement::ConnectionPreparation;
use crate::service_management::{
    LAUNCH_AGENT_PLIST, map_status_code, operation_error, validate_registration_version,
};

const SERVICE_REQUIREMENT: &str = concat!(
    "identifier \"com.runne.credential-service\" and anchor apple generic and ",
    "certificate leaf[subject.OU] = \"758F9Z45SR\" and ",
    "cdhash H\"1111111111111111111111111111111111111111\"",
);
const DESKTOP_REQUIREMENT: &str = concat!(
    "identifier \"com.runne.desktop\" and anchor apple generic and ",
    "certificate leaf[subject.OU] = \"758F9Z45SR\" and ",
    "cdhash H\"2222222222222222222222222222222222222222\"",
);

fn configuration(role: CredentialServiceEndpointRole) -> CredentialServiceEndpointConfiguration {
    CredentialServiceEndpointConfiguration::new(
        role,
        role.endpoint_name(),
        CredentialServicePeerRequirement::new(SERVICE_REQUIREMENT).unwrap(),
        CredentialServicePeerRequirement::new(DESKTOP_REQUIREMENT).unwrap(),
    )
    .unwrap()
}

#[test]
fn each_role_accepts_only_its_exact_endpoint_and_requirements() {
    for role in [
        CredentialServiceEndpointRole::Desktop,
        CredentialServiceEndpointRole::Runtime,
        CredentialServiceEndpointRole::Writer,
    ] {
        let exact = configuration(role);
        assert_eq!(exact.role(), role);
        assert_eq!(exact.endpoint_name(), role.endpoint_name());
        let desktop_endpoint = CredentialServiceEndpointConfiguration::new(
            role,
            CredentialServiceEndpointRole::Desktop.endpoint_name(),
            CredentialServicePeerRequirement::new(SERVICE_REQUIREMENT).unwrap(),
            CredentialServicePeerRequirement::new(DESKTOP_REQUIREMENT).unwrap(),
        );
        if role == CredentialServiceEndpointRole::Desktop {
            assert_eq!(desktop_endpoint, Ok(exact));
        } else {
            assert_eq!(desktop_endpoint, Err(CredentialServiceXpcError::Rejected));
        }
    }
    assert!(CredentialServicePeerRequirement::new("").is_err());
    assert!(CredentialServicePeerRequirement::new("(").is_err());
    assert!(CredentialServicePeerRequirement::new("identifier \"altered\"\0").is_err());
}

#[test]
fn signing_requirement_must_be_installed_before_resume() {
    let mut preparation = ConnectionPreparation::new();
    assert_eq!(
        preparation.resume(),
        Err(CredentialServiceXpcError::Rejected)
    );
    preparation
        .install_requirement(CredentialServicePeerRequirement::new(SERVICE_REQUIREMENT).unwrap())
        .unwrap();
    preparation.resume().unwrap();
    assert_eq!(
        preparation.install_requirement(
            CredentialServicePeerRequirement::new(SERVICE_REQUIREMENT).unwrap()
        ),
        Err(CredentialServiceXpcError::Rejected)
    );
}

#[test]
fn service_management_status_and_version_skew_are_closed() {
    assert_eq!(LAUNCH_AGENT_PLIST, "com.runne.credential-service.plist");
    assert_eq!(
        map_status_code(0),
        CredentialServiceRegistrationStatus::NotRegistered
    );
    assert_eq!(
        map_status_code(1),
        CredentialServiceRegistrationStatus::Enabled
    );
    assert_eq!(
        map_status_code(2),
        CredentialServiceRegistrationStatus::RequiresApproval
    );
    assert_eq!(
        map_status_code(3),
        CredentialServiceRegistrationStatus::NotFound
    );
    assert_eq!(
        map_status_code(99),
        CredentialServiceRegistrationStatus::Unavailable
    );
    assert_eq!(validate_registration_version("v3", "v3"), Ok(()));
    assert_eq!(
        validate_registration_version("v2", "v3"),
        Err(CredentialServiceXpcError::VersionSkew)
    );
    assert_eq!(
        operation_error(CredentialServiceRegistrationStatus::RequiresApproval),
        CredentialServiceXpcError::ApprovalRequired
    );
    assert_eq!(
        operation_error(CredentialServiceRegistrationStatus::NotFound),
        CredentialServiceXpcError::NotFound
    );
    assert_eq!(
        operation_error(CredentialServiceRegistrationStatus::Unavailable),
        CredentialServiceXpcError::Unavailable
    );
}

struct Echo;
impl CredentialServiceRequestHandler for Echo {
    fn handle(
        &self,
        _role: CredentialServiceEndpointRole,
        request: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
        Ok(request)
    }
}

#[test]
fn listener_surface_accepts_rust_handler_without_foundation_objects() {
    fn accepts_handler(_: Arc<dyn CredentialServiceRequestHandler>) {}
    accepts_handler(Arc::new(Echo));
}

const HANDLER_CANARY: &str = "runne-d1-1c-handler-canary-c824d9";

struct Panics(Arc<AtomicUsize>);
impl CredentialServiceRequestHandler for Panics {
    fn handle(
        &self,
        _role: CredentialServiceEndpointRole,
        request: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
        struct UnwindWitness(Arc<AtomicUsize>);
        impl Drop for UnwindWitness {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let _unwind = UnwindWitness(Arc::clone(&self.0));
        assert_eq!(request.as_slice(), HANDLER_CANARY.as_bytes());
        panic!("secret-free test panic")
    }
}

#[test]
fn handler_panic_is_closed_before_the_objective_c_boundary() {
    let unwind_events = Arc::new(AtomicUsize::new(0));
    let error = crate::listener::invoke_handler(
        &Panics(Arc::clone(&unwind_events)),
        CredentialServiceEndpointRole::Desktop,
        Zeroizing::new(HANDLER_CANARY.as_bytes().to_vec()),
    )
    .unwrap_err();
    assert_eq!(unwind_events.load(Ordering::Acquire), 1);
    assert_eq!(error, CredentialServiceXpcError::Unavailable);
    assert_eq!(
        error.to_string(),
        "credential service native transport failed"
    );
    assert!(!format!("{error:?}").contains(HANDLER_CANARY));
}

#[cfg(target_os = "macos")]
#[test]
fn native_protocol_interface_is_constructible() {
    let _interface = crate::frame::native::interface();
}

#[cfg(target_os = "macos")]
#[test]
fn native_client_installs_canonical_requirement() {
    assert!(
        CredentialServiceDesktopXpcClient::connect(configuration(
            CredentialServiceEndpointRole::Desktop
        ))
        .is_ok()
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn cancellation_and_expiry_before_dispatch_remain_definitive() {
    use runne_platform_ports::credential_service::{
        CredentialServiceCallContext, CredentialServiceDesktopPort,
        CredentialServiceDesktopRequest, CredentialServicePortError,
    };

    let client = CredentialServiceDesktopXpcClient::connect(configuration(
        CredentialServiceEndpointRole::Desktop,
    ))
    .unwrap();
    let cancelled = runne_platform_ports::credential_service::CredentialServiceCancellation::new();
    cancelled.cancel();
    let request =
        || CredentialServiceDesktopRequest::from_zeroizing(Zeroizing::new(vec![1])).unwrap();
    assert!(matches!(
        client
            .challenge(
                request(),
                CredentialServiceCallContext::new(
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                    cancelled,
                ),
            )
            .await,
        Err(CredentialServicePortError::Cancelled)
    ));

    let expired = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(1))
        .unwrap();
    assert!(matches!(
        client
            .challenge(
                request(),
                CredentialServiceCallContext::new(
                    expired,
                    runne_platform_ports::credential_service::CredentialServiceCancellation::new(),
                ),
            )
            .await,
        Err(CredentialServicePortError::TimedOut)
    ));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn non_macos_transport_is_typed_unsupported() {
    assert!(matches!(
        CredentialServiceDesktopXpcClient::connect(configuration(
            CredentialServiceEndpointRole::Desktop
        )),
        Err(CredentialServiceXpcError::Unsupported)
    ));
}

#[path = "tests/runtime_client.rs"]
mod runtime_client;
