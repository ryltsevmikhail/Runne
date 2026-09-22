//! One-shot framed transport plumbing for daemon-bound writer evidence:
//! bounded reads, transfer timeouts, and domain-separated transcripts.

use std::io::Read;
use std::os::unix::net::UnixStream;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::TRANSFER_TIMEOUT;

pub(super) fn read_one_shot<const BYTES: usize>(
    transport: &mut UnixStream,
) -> Result<[u8; BYTES], BrokerHandoffError> {
    let mut received = Vec::with_capacity(BYTES + 1);
    transport
        .take((BYTES + 1) as u64)
        .read_to_end(&mut received)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    received
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)
}

pub(super) fn configure(stream: &UnixStream) -> Result<(), BrokerHandoffError> {
    let timeout = transfer_timeout();
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| BrokerHandoffError::Unavailable)
}

#[cfg(feature = "test-support")]
fn transfer_timeout() -> std::time::Duration {
    let opted_in = std::env::var_os("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    transfer_timeout_for_local_test_opt_in(opted_in)
}

#[cfg(any(test, feature = "test-support"))]
pub(in crate::provider_credential_broker) const fn transfer_timeout_for_local_test_opt_in(
    opted_in: bool,
) -> std::time::Duration {
    if opted_in {
        std::time::Duration::from_mins(2)
    } else {
        TRANSFER_TIMEOUT
    }
}

#[cfg(not(feature = "test-support"))]
const fn transfer_timeout() -> std::time::Duration {
    TRANSFER_TIMEOUT
}

pub(super) fn transcript(tag: &[u8], record: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(tag.len() + record.len());
    transcript.extend_from_slice(tag);
    transcript.extend_from_slice(record);
    transcript
}
