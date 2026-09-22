use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
pub(in crate::provider_credential_broker) fn observed_start_identity(
    pid: u32,
) -> Result<[u8; 32], BrokerHandoffError> {
    let process_stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let tail = process_stat
        .rsplit_once(')')
        .map(|(_, tail)| tail)
        .ok_or(BrokerHandoffError::Rejected)?;
    let start_time = tail
        .split_whitespace()
        .nth(19)
        .ok_or(BrokerHandoffError::Rejected)?;
    let mut digest = Sha256::new();
    digest.update(b"gocode.provider-credential-writer.start.v1");
    digest.update(pid.to_be_bytes());
    digest.update(start_time.as_bytes());
    Ok(digest.finalize().into())
}

#[cfg(target_os = "macos")]
pub(in crate::provider_credential_broker) fn observed_start_identity(
    pid: u32,
) -> Result<[u8; 32], BrokerHandoffError> {
    let pid = std::num::NonZeroU32::new(pid).ok_or(BrokerHandoffError::Rejected)?;
    runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
        .map(|identity| identity.digest())
        .map_err(|_| BrokerHandoffError::Rejected)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(in crate::provider_credential_broker) fn observed_start_identity(
    _pid: u32,
) -> Result<[u8; 32], BrokerHandoffError> {
    Err(BrokerHandoffError::Unavailable)
}
