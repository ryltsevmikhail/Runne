use runne_api::MacOsCodeIdentityExpectationV1;
use runne_macos_xpc::{
    QualificationRunnerEndpoint, QualificationRunnerEndpointConfiguration,
    QualificationRunnerPeerRequirement, QualificationRunnerSessionBinding,
    QualificationRunnerXpcError, current_login_session_binding,
};

use super::VerifiedQualificationBootstrapClientPins;

impl VerifiedQualificationBootstrapClientPins {
    /// Builds only the fixed desktop-bootstrap endpoint from current login facts.
    pub fn desktop_bootstrap_configuration(
        &self,
    ) -> Result<QualificationRunnerEndpointConfiguration, QualificationRunnerXpcError> {
        self.bootstrap_configuration(
            QualificationRunnerEndpoint::DesktopBootstrap,
            self.descriptor.desktop_identity(),
        )
    }

    /// Builds only the fixed runtime-bootstrap endpoint from current login facts.
    pub fn runtime_bootstrap_configuration(
        &self,
    ) -> Result<QualificationRunnerEndpointConfiguration, QualificationRunnerXpcError> {
        self.bootstrap_configuration(
            QualificationRunnerEndpoint::RuntimeBootstrap,
            self.descriptor.runtime_identity(),
        )
    }

    /// Builds the fixed root-consume endpoint with root and live GUI session pins.
    pub fn root_consume_configuration(
        &self,
    ) -> Result<QualificationRunnerEndpointConfiguration, QualificationRunnerXpcError> {
        if !self.current() {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        QualificationRunnerEndpointConfiguration::new(
            QualificationRunnerEndpoint::RootConsume,
            requirement(self.descriptor.root_identity())?,
            requirement(self.descriptor.executor_identity())?,
            current_login_session_binding()?,
            QualificationRunnerSessionBinding::new(0, 0)?,
        )
    }

    fn bootstrap_configuration(
        &self,
        endpoint: QualificationRunnerEndpoint,
        client: &MacOsCodeIdentityExpectationV1,
    ) -> Result<QualificationRunnerEndpointConfiguration, QualificationRunnerXpcError> {
        if !self.current() {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        let session = current_login_session_binding()?;
        QualificationRunnerEndpointConfiguration::new(
            endpoint,
            requirement(self.descriptor.executor_identity())?,
            requirement(client)?,
            session,
            session,
        )
    }
}

fn requirement(
    identity: &MacOsCodeIdentityExpectationV1,
) -> Result<QualificationRunnerPeerRequirement, QualificationRunnerXpcError> {
    QualificationRunnerPeerRequirement::new(
        crate::updater_metadata::macos_identity::MacOsCodeIdentityV1::from_expectation(identity)
            .requirement(),
    )
}
