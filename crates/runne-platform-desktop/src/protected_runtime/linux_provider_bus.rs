#[cfg(any(test, feature = "test-support"))]
use std::path::Path;
use std::process::Command;

use super::ProtectedBundledRuntimeLaunchSpec;
use crate::{
    ProtectedBundledRuntimeError, provider_credential_broker::ValidatedLinuxSessionBusAddress,
};

pub(super) fn address_for_launch(
    spec: &ProtectedBundledRuntimeLaunchSpec,
) -> Result<Option<ValidatedLinuxSessionBusAddress>, ProtectedBundledRuntimeError> {
    // Test-support seam: an injected address was already validated through
    // the strict production checks, so the launch-time lookup is skipped.
    // Production builds never carry the injected field.
    #[cfg(any(test, feature = "test-support"))]
    if let Some(address) = validated_session_bus_address(spec) {
        return Ok(Some(address.clone()));
    }
    if spec.provider_activation().is_some() {
        ValidatedLinuxSessionBusAddress::for_production()
            .map(Some)
            .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)
    } else {
        Ok(None)
    }
}

pub(super) fn apply_to_command(
    command: &mut Command,
    provider_bound: bool,
    address: Option<&ValidatedLinuxSessionBusAddress>,
) -> Result<(), ProtectedBundledRuntimeError> {
    if !provider_bound {
        return Ok(());
    }
    let address = address.ok_or(ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    command.env("DBUS_SESSION_BUS_ADDRESS", address.as_str());
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
const fn validated_session_bus_address(
    spec: &ProtectedBundledRuntimeLaunchSpec,
) -> Option<&ValidatedLinuxSessionBusAddress> {
    spec.validated_session_bus_address.as_ref()
}

#[cfg(any(test, feature = "test-support"))]
impl ProtectedBundledRuntimeLaunchSpec {
    /// Test-support seam for Linux provider-bound launches: binds one real
    /// fixture session-bus socket to this in-memory launch spec.
    ///
    /// The socket path is re-validated through the exact strict production
    /// checks (absolute path, socket file type, own-euid ownership), so the
    /// seam only removes the dependency on a host-provided
    /// `/run/user/<euid>/bus`; it never relaxes validation. Production
    /// builds do not carry this constructor.
    ///
    /// # Errors
    ///
    /// Returns a closed runtime-root failure when the fixture path is not a
    /// strictly valid session-bus socket owned by the effective uid.
    pub fn with_validated_session_bus_address(
        mut self,
        socket_path: &Path,
    ) -> Result<Self, ProtectedBundledRuntimeError> {
        let address = ValidatedLinuxSessionBusAddress::for_tests(socket_path)
            .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        self.validated_session_bus_address = Some(address);
        Ok(self)
    }
}
