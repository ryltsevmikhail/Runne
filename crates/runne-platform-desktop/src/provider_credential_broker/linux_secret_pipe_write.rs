//! Whole-envelope write deadline; a stopped writer cannot block the host.
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
use std::{
    fs::File,
    io::Write as _,
    os::fd::AsFd as _,
    time::{Duration, Instant},
};

pub(super) fn write_bounded(
    file: &mut File,
    mut bytes: &[u8],
    budget: Duration,
) -> Result<(), BrokerHandoffError> {
    let flags = fcntl(&*file, FcntlArg::F_GETFL).map_err(|_| BrokerHandoffError::Unavailable)?;
    fcntl(
        &*file,
        FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
    )
    .map_err(|_| BrokerHandoffError::Unavailable)?;
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or(BrokerHandoffError::Unavailable)?;
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(BrokerHandoffError::Unavailable)?;
        let mut descriptors = [PollFd::new(file.as_fd(), PollFlags::POLLOUT)];
        let ready = poll(
            &mut descriptors,
            PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX),
        )
        .map_err(|_| BrokerHandoffError::Unavailable)?;
        let events = descriptors[0].revents().unwrap_or(PollFlags::POLLNVAL);
        if ready == 0
            || events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
        {
            return Err(BrokerHandoffError::Unavailable);
        }
        match file.write(bytes) {
            Ok(0) => return Err(BrokerHandoffError::Unavailable),
            Ok(count) => bytes = &bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(BrokerHandoffError::Unavailable),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_reader_receives_the_complete_envelope_and_eof() {
        use std::io::Read as _;
        let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            File::from(reader).read_to_end(&mut bytes).unwrap();
            bytes
        });
        let envelope = vec![17; 65_536];
        let mut writer = File::from(writer);
        let result = write_bounded(&mut writer, &envelope, Duration::from_secs(1));
        drop(writer);
        let observed = reader.join().unwrap();
        result.unwrap();
        assert_eq!(observed, envelope);
    }

    #[test]
    fn stalled_reader_is_bounded_and_closed_reader_is_rejected() {
        let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let mut writer = File::from(writer);
        fcntl(&writer, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        loop {
            match writer.write(&[0; 4096]) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("fill pipe: {e}"),
            }
        }
        let start = Instant::now();
        assert!(write_bounded(&mut writer, b"sealed", Duration::from_millis(20)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(reader);
        assert!(write_bounded(&mut writer, b"sealed", Duration::from_secs(1)).is_err());
    }
}
