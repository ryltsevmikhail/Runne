//! Strictly validated session-bus address for the Linux writer spawn
//! profile, split from the spawn core so each responsibility stays bounded.
//! Production uses only the euid-derived canonical socket; tests may
//! validate a private fixture socket through the same strict checks
//! (absolute path, socket type, own-euid ownership).

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

/// Strictly validated session-bus address. Production uses only the
/// euid-derived canonical socket; tests may validate a private fixture
/// socket through the same strict checks (absolute path, socket type,
/// own-euid ownership).
#[derive(Clone, Eq, PartialEq)]
pub struct SessionBusAddress(String);

impl SessionBusAddress {
    /// Production derivation: `/run/user/<euid>/bus`, validated before use.
    pub fn for_production() -> Result<Self, BrokerHandoffError> {
        let address = format!("unix:path=/run/user/{}/bus", effective_uid());
        let path = address
            .strip_prefix("unix:path=")
            .ok_or(BrokerHandoffError::Rejected)?;
        probe_path_socket(std::path::Path::new(path))?;
        Ok(Self(address))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(socket_path: &std::path::Path) -> Result<Self, BrokerHandoffError> {
        probe_path_socket(socket_path)?;
        Ok(Self(format!("unix:path={}", socket_path.to_string_lossy())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub(super) fn probe_path_socket(path: &std::path::Path) -> Result<(), BrokerHandoffError> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    if !path.is_absolute() {
        return Err(BrokerHandoffError::Rejected);
    }
    let metadata = std::fs::metadata(path).map_err(|_| BrokerHandoffError::Unavailable)?;
    if !metadata.file_type().is_socket() || metadata.uid() != effective_uid() {
        return Err(BrokerHandoffError::Unavailable);
    }
    Ok(())
}

fn effective_uid() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    // /proc/self ownership mirrors our effective uid; not a secret read.
    std::fs::metadata("/proc/self").map_or(u32::MAX, |metadata| metadata.uid())
}
