use super::*;
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Duration;

fn terminal_pair() -> (File, File) {
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    unsafe {
        (
            File::from(OwnedFd::from_raw_fd(master)),
            File::from(OwnedFd::from_raw_fd(slave)),
        )
    }
}

fn attributes(file: &File) -> libc::termios {
    let mut value = std::mem::MaybeUninit::uninit();
    assert_eq!(
        unsafe { libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()) },
        0
    );
    unsafe { value.assume_init() }
}

fn prompt_and_send(
    input: &'static [u8],
) -> (
    Result<Zeroizing<Vec<u8>>, InputError>,
    Vec<u8>,
    libc::termios,
    libc::termios,
) {
    let (mut master, mut slave) = terminal_pair();
    let before = attributes(&slave);
    let mut copy = slave.try_clone().unwrap();
    let worker = std::thread::spawn(move || {
        let mut ready = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut ready, 1, 1000) },
            1,
            "host did not present its prompt"
        );
        let mut prompt = [0; 9];
        master.read_exact(&mut prompt).unwrap();
        assert_eq!(&prompt, b"API key: ");
        assert_eq!(attributes(&master).c_lflag & libc::ECHO, 0);
        master.write_all(input).unwrap();
        let mut output = [0; 32];
        // Poll the owned PTY rather than blocking indefinitely on output.
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
        let length = master.read(&mut output).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        output[..length].to_vec()
    });
    let result = read_secret(&mut slave);
    let after = attributes(&copy);
    // Keep the slave descriptor live while the master observes completion.
    copy.flush().unwrap();
    (result, worker.join().unwrap(), before, after)
}

#[test]
fn key_is_not_echoed_and_terminal_is_restored() {
    let (result, output, before, after) = prompt_and_send(b"synthetic-key\n");
    assert_eq!(result.unwrap().as_slice(), b"synthetic-key");
    assert!(!output.windows(9).any(|bytes| bytes == b"synthetic"));
    assert_restored(&before, &after);
}

#[test]
fn ctrl_c_cancels_without_returning_partial_key_and_restores_terminal() {
    let (result, _, before, after) = prompt_and_send(b"partial\x03");
    assert_eq!(result.unwrap_err(), InputError::Cancelled);
    assert_restored(&before, &after);
}

#[test]
fn empty_or_control_bearing_key_is_rejected() {
    for input in [b"\n".as_slice(), b"a\tb\n".as_slice()] {
        let (result, _, before, after) = prompt_and_send(input);
        assert_eq!(result.unwrap_err(), InputError::Invalid);
        assert_restored(&before, &after);
    }
}

#[test]
fn ordinary_file_is_rejected_before_input_or_output() {
    let mut file = File::open("/dev/null").unwrap();
    assert_eq!(read_secret(&mut file).unwrap_err(), InputError::Unavailable);
}

fn assert_restored(before: &libc::termios, after: &libc::termios) {
    assert_eq!(before.c_lflag, after.c_lflag);
    assert_eq!(before.c_iflag, after.c_iflag);
    assert_eq!(before.c_oflag, after.c_oflag);
    assert_eq!(before.c_cflag, after.c_cflag);
    assert_eq!(before.c_cc, after.c_cc);
}
#[test]
fn backspace_erases_and_ctrl_d_cancels() {
    assert_eq!(
        prompt_and_send(b"testX\x7f-key\n").0.unwrap().as_slice(),
        b"test-key"
    );
    let (result, _, before, after) = prompt_and_send(b"partial\x04");
    assert_eq!(result.unwrap_err(), InputError::Cancelled);
    assert_restored(&before, &after);
}
#[test]
fn overlong_key_is_rejected_without_echo() {
    let oversized: &'static [u8] = Box::leak(vec![b'x'; 4097].into_boxed_slice());
    let (result, output, before, after) = prompt_and_send(oversized);
    assert_eq!(result.unwrap_err(), InputError::Invalid);
    assert!(!output.contains(&b'x'));
    assert_restored(&before, &after);
}

#[test]
fn termination_signal_cancels_input_and_restores_terminal() {
    let (mut master, mut slave) = terminal_pair();
    let before = attributes(&slave);
    let reader = unsafe { libc::pthread_self() };
    let worker = std::thread::spawn(move || {
        let mut descriptor = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 1000) }, 1);
        let mut prompt = [0; 9];
        master.read_exact(&mut prompt).unwrap();
        assert_eq!(&prompt, b"API key: ");
        assert_eq!(unsafe { libc::pthread_kill(reader, libc::SIGTERM) }, 0);
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 2000) }, 1);
        let mut output = [0; 16];
        master.read(&mut output).unwrap();
        // Keep the PTY open until the reader has restored terminal state.
        std::thread::sleep(Duration::from_millis(25));
    });
    assert_eq!(read_secret(&mut slave).unwrap_err(), InputError::Cancelled);
    assert_restored(&before, &attributes(&slave));
    worker.join().unwrap();
}

#[test]
fn bracketed_paste_accepts_only_payload_without_echo() {
    let (result, output, before, after) =
        prompt_and_send(b"\x1b[200~synthetic-pasted-key\x1b[201~\r");
    assert_eq!(result.unwrap().as_slice(), b"synthetic-pasted-key");
    assert!(!output.windows(9).any(|bytes| bytes == b"synthetic"));
    assert_restored(&before, &after);
}

#[test]
fn paste_controls_and_malformed_markers_never_submit() {
    for input in [
        b"\x1b[200~synthetic\n".as_slice(),
        b"\x1b[200~synthetic\r".as_slice(),
        b"\x1b[201~\r".as_slice(),
        b"\x1b[200~synthetic\x1b[200~".as_slice(),
        b"\x1b[20X".as_slice(),
        b"\x1b[200~synthetic\t".as_slice(),
    ] {
        let (result, output, before, after) = prompt_and_send(input);
        assert_eq!(result.unwrap_err(), InputError::Invalid);
        assert!(!output.windows(9).any(|bytes| bytes == b"synthetic"));
        assert_restored(&before, &after);
    }
}

#[test]
fn plain_paste_and_multiple_bracketed_pastes_support_editing() {
    for input in [
        b"synthetic-pasted-key\r".as_slice(),
        b"\x1b[200~synthetic\x1b[201~-\x1b[200~pasted-keyX\x1b[201~\x7f\r".as_slice(),
    ] {
        let (result, output, before, after) = prompt_and_send(input);
        assert_eq!(result.unwrap().as_slice(), b"synthetic-pasted-key");
        assert!(!output.windows(9).any(|bytes| bytes == b"synthetic"));
        assert_restored(&before, &after);
    }
}

#[test]
fn fragmented_paste_waits_for_enter_with_echo_disabled() {
    let (mut master, mut slave) = terminal_pair();
    let before = attributes(&slave);
    let worker = std::thread::spawn(move || {
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
        let mut prompt = [0; 9];
        master.read_exact(&mut prompt).unwrap();
        for chunk in [
            b"\x1b[2".as_slice(),
            b"00~synthetic".as_slice(),
            b"-key\x1b[20".as_slice(),
            b"1~".as_slice(),
        ] {
            master.write_all(chunk).unwrap();
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 30) }, 0);
            assert_eq!(attributes(&master).c_lflag & libc::ECHO, 0);
        }
        master.write_all(b"\r").unwrap();
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
        let mut output = [0; 32];
        let length = master.read(&mut output).unwrap();
        assert!(
            !output[..length]
                .windows(9)
                .any(|bytes| bytes == b"synthetic")
        );
        std::thread::sleep(Duration::from_millis(20));
    });
    assert_eq!(
        read_secret(&mut slave).unwrap().as_slice(),
        b"synthetic-key"
    );
    assert_restored(&before, &attributes(&slave));
    worker.join().unwrap();
}
