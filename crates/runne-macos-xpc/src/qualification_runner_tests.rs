use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{
    CredentialServiceEndpointRole, QualificationRunnerEndpoint,
    QualificationRunnerEndpointConfiguration, QualificationRunnerPeer,
    QualificationRunnerPeerRequirement, QualificationRunnerReply, QualificationRunnerRequest,
    QualificationRunnerSession, QualificationRunnerSessionBinding,
    QualificationRunnerSessionContext, QualificationRunnerSessionFactory,
    QualificationRunnerSessionLease, QualificationRunnerSessionReceipt,
    QualificationRunnerXpcClient, QualificationRunnerXpcError,
};

const SERVICE: &str = concat!(
    "identifier \"com.runne.qualification-runner\" and anchor apple generic and ",
    "certificate leaf[subject.OU] = \"758F9Z45SR\" and ",
    "cdhash H\"1111111111111111111111111111111111111111\"",
);
const CLIENT: &str = concat!(
    "identifier \"com.runne.desktop\" and anchor apple generic and ",
    "certificate leaf[subject.OU] = \"758F9Z45SR\" and ",
    "cdhash H\"2222222222222222222222222222222222222222\"",
);

fn configuration(
    endpoint: QualificationRunnerEndpoint,
) -> QualificationRunnerEndpointConfiguration {
    let service_binding = if endpoint == QualificationRunnerEndpoint::RootConsume {
        QualificationRunnerSessionBinding::new(0, 0).unwrap()
    } else {
        QualificationRunnerSessionBinding::new(501, 1).unwrap()
    };
    QualificationRunnerEndpointConfiguration::new(
        endpoint,
        QualificationRunnerPeerRequirement::new(SERVICE).unwrap(),
        QualificationRunnerPeerRequirement::new(CLIENT).unwrap(),
        QualificationRunnerSessionBinding::new(501, 42).unwrap(),
        service_binding,
    )
    .unwrap()
}

#[test]
fn endpoints_are_fixed_and_root_consume_cannot_use_bootstrap_client() {
    let root = configuration(QualificationRunnerEndpoint::RootConsume);
    let desktop = configuration(QualificationRunnerEndpoint::DesktopBootstrap);
    assert!(matches!(
        QualificationRunnerXpcClient::connect_bootstrap(&root),
        Err(QualificationRunnerXpcError::Rejected)
    ));
    assert!(matches!(
        QualificationRunnerXpcClient::connect_root_consume(&desktop),
        Err(QualificationRunnerXpcError::Rejected)
    ));
    assert_ne!(
        QualificationRunnerEndpoint::DesktopBootstrap.mach_service_name(),
        QualificationRunnerEndpoint::RuntimeBootstrap.mach_service_name()
    );
    assert_eq!(
        [
            CredentialServiceEndpointRole::Desktop,
            CredentialServiceEndpointRole::Runtime,
            CredentialServiceEndpointRole::Writer,
        ]
        .len(),
        3
    );
}

#[test]
fn session_binding_rejects_zero_login_session_and_non_root_root_service() {
    let requirement = || QualificationRunnerPeerRequirement::new(SERVICE).unwrap();
    let client = || QualificationRunnerPeerRequirement::new(CLIENT).unwrap();
    assert!(
        QualificationRunnerEndpointConfiguration::new(
            QualificationRunnerEndpoint::DesktopBootstrap,
            requirement(),
            client(),
            QualificationRunnerSessionBinding::new(501, 0).unwrap(),
            QualificationRunnerSessionBinding::new(501, 1).unwrap(),
        )
        .is_err()
    );
    assert!(
        QualificationRunnerEndpointConfiguration::new(
            QualificationRunnerEndpoint::RootConsume,
            requirement(),
            client(),
            QualificationRunnerSessionBinding::new(501, 42).unwrap(),
            QualificationRunnerSessionBinding::new(501, 0).unwrap(),
        )
        .is_err()
    );
    assert!(QualificationRunnerSessionBinding::new(0, -1).is_err());
}

#[test]
fn runner_frames_are_bounded_and_are_not_credential_frames() {
    assert!(QualificationRunnerRequest::from_zeroizing(Zeroizing::new(Vec::new())).is_err());
    assert!(
        QualificationRunnerReply::from_zeroizing(Zeroizing::new(vec![
            0;
            crate::qualification_runner::MAX_QUALIFICATION_RUNNER_FRAME_BYTES
                + 1
        ]))
        .is_err()
    );
    let request = QualificationRunnerRequest::from_zeroizing(Zeroizing::new(vec![9])).unwrap();
    assert_eq!(&*request.into_zeroizing(), &[9]);
    assert!(crate::frame::NativeRequestFrame::new(Zeroizing::new(vec![0; 16 * 1024 + 1])).is_err());
}

struct Session;

impl QualificationRunnerSession for Session {
    fn exchange(
        &mut self,
        request: QualificationRunnerRequest,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
        QualificationRunnerReply::from_zeroizing(request.into_zeroizing())
    }
}

struct Factory;

impl QualificationRunnerSessionFactory for Factory {
    fn create_session(
        &self,
        context: QualificationRunnerSessionContext,
    ) -> Result<QualificationRunnerSessionLease, QualificationRunnerXpcError> {
        if context.endpoint() != QualificationRunnerEndpoint::RuntimeBootstrap {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        let peer = context.peer();
        let _receipt = context.into_receipt();
        if peer.euid() == 501 && peer.audit_session() == 42 {
            QualificationRunnerSessionLease::new(
                Box::new(Session),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
        } else {
            Err(QualificationRunnerXpcError::Rejected)
        }
    }
}

#[test]
fn session_factory_requires_os_observed_directional_binding() {
    let factory: Arc<dyn QualificationRunnerSessionFactory> = Arc::new(Factory);
    assert!(
        factory
            .create_session(QualificationRunnerSessionContext::new(
                QualificationRunnerEndpoint::RuntimeBootstrap,
                QualificationRunnerPeer::new(501, 42),
                QualificationRunnerSessionReceipt::random().unwrap(),
            ),)
            .is_ok()
    );
    assert!(matches!(
        factory.create_session(QualificationRunnerSessionContext::new(
            QualificationRunnerEndpoint::RootConsume,
            QualificationRunnerPeer::new(502, 42),
            QualificationRunnerSessionReceipt::random().unwrap(),
        ),),
        Err(QualificationRunnerXpcError::Rejected)
    ));
}
