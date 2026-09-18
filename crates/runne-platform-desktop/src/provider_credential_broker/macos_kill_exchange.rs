use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

#[cfg(not(feature = "test-support"))]
const OWNERSHIP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn configure(transport: &UnixStream) -> Result<(), BrokerHandoffError> {
    let timeout = ownership_timeout();
    transport
        .set_read_timeout(Some(timeout))
        .and_then(|()| transport.set_write_timeout(Some(timeout)))
        .map_err(|_| BrokerHandoffError::Unavailable)
}

#[cfg(feature = "test-support")]
const fn ownership_timeout() -> Duration {
    // Workspace test hosts run the whole matrix concurrently and can starve
    // a test thread well past the production budget (observed as a BrokenPipe
    // in v3_control_completes_the_full_broker_writer_handoff on a loaded CI
    // mac lane: the daemon's 5s read deadline fired before the desktop side
    // wrote the relinquished wire). Keep the exchange bounded but generous in
    // test-support builds; production keeps the 5s budget. The
    // RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST env stays scoped to the local
    // native enrollment fixture route and no longer widens this timeout.
    Duration::from_mins(2)
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
    fn test_builds_get_a_bounded_ownership_budget() {
        assert_eq!(ownership_timeout(), Duration::from_mins(2));
    }
}
