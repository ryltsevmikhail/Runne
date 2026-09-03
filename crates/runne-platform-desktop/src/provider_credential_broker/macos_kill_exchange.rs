use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

const OWNERSHIP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn configure(transport: &UnixStream) -> Result<(), BrokerHandoffError> {
    let timeout = ownership_timeout();
    transport
        .set_read_timeout(Some(timeout))
        .and_then(|()| transport.set_write_timeout(Some(timeout)))
        .map_err(|_| BrokerHandoffError::Unavailable)
}

#[cfg(feature = "test-support")]
fn ownership_timeout() -> Duration {
    let opted_in = std::env::var_os("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    ownership_timeout_for_local_test_opt_in(opted_in)
}

#[cfg(feature = "test-support")]
const fn ownership_timeout_for_local_test_opt_in(opted_in: bool) -> Duration {
    if opted_in {
        Duration::from_mins(2)
    } else {
        OWNERSHIP_TIMEOUT
    }
}

#[cfg(not(feature = "test-support"))]
const fn ownership_timeout() -> Duration {
    OWNERSHIP_TIMEOUT
}

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

pub(super) fn write_one_shot(
    transport: &mut UnixStream,
    wire: &[u8],
) -> Result<(), BrokerHandoffError> {
    transport
        .write_all(wire)
        .and_then(|()| transport.shutdown(Shutdown::Write))
        .map_err(|_| BrokerHandoffError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_phase_rejects_an_extra_byte() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            sender.write_all(&[1, 2, 3, 4, 5]).unwrap();
            sender.shutdown(Shutdown::Write).unwrap();
        });
        assert!(read_one_shot::<4>(&mut receiver).is_err());
        writer.join().unwrap();
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn isolated_native_enrollment_gets_a_bounded_ownership_budget() {
        assert_eq!(
            ownership_timeout_for_local_test_opt_in(false),
            Duration::from_secs(5)
        );
        assert_eq!(
            ownership_timeout_for_local_test_opt_in(true),
            Duration::from_mins(2)
        );
    }
}
