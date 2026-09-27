use std::process::Command;

use crate::{
    ProtectedBundledRuntimeError, provider_credential_broker::ValidatedLinuxSessionBusAddress,
};

pub(super) fn address_for_launch(
    provider_bound: bool,
) -> Result<Option<ValidatedLinuxSessionBusAddress>, ProtectedBundledRuntimeError> {
    if provider_bound {
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
