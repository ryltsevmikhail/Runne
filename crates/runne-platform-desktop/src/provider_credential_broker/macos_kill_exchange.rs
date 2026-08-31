use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

const OWNERSHIP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn configure(transport: &UnixStream) -> Result<(), BrokerHandoffError> {
    transport
        .set_read_timeout(Some(OWNERSHIP_TIMEOUT))
        .and_then(|()| transport.set_write_timeout(Some(OWNERSHIP_TIMEOUT)))
        .map_err(|_| BrokerHandoffError::Unavailable)
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
}
