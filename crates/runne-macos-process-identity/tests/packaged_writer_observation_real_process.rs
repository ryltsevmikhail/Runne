#![cfg(target_os = "macos")]
#![allow(
    clippy::borrow_as_ptr,
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    reason = "test-only SCM_RIGHTS fixture mirrors the fixed native wire layout"
)]

use std::fs;
use std::io::IoSlice;
use std::mem::size_of;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1;

const ROLE_ENV: &str = "RUNNE_B2B2II_REAL_PROCESS_ROLE";
const WRITER_ENV: &str = "RUNNE_B2B2II_WRITER_PATH";
const TEST_NAME: &str = "packaged_runned_creates_control_stream_and_writer_reaches_pending";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[test]
fn packaged_runned_creates_control_stream_and_writer_reaches_pending() {
    match std::env::var(ROLE_ENV).as_deref() {
        Ok("runne") => return writer_helper(),
        Ok("runned") => return daemon_helper(),
        _ => {}
    }

    let package = TestPackage::new();
    let output = Command::new(package.daemon())
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(ROLE_ENV, "runned")
        .env(WRITER_ENV, package.writer())
        .output()
        .expect("launch packaged runned helper");
    assert!(
        output.status.success(),
        "runned helper failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn writer_helper() {
    let handoff = MacOsUntrustedWriterEndpointHandoffV1::receive_from_stdin()
        .expect("receive exact writer handoff");
    if let Err(error) = handoff.observe_pending_packaged_writer() {
        panic!("packaged writer did not reach low-level Pending: {error:?}");
    }
}

fn daemon_helper() {
    let writer = std::env::var_os(WRITER_ENV).expect("writer path");
    let (ingress_sender, ingress_receiver) = UnixStream::pair().expect("ingress pair");
    let (daemon_control, writer_control) = UnixStream::pair().expect("control pair");
    let child = Command::new(writer)
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(ROLE_ENV, "runne")
        .stdin(Stdio::from(OwnedFd::from(ingress_receiver)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch packaged runne helper");
    send_handoff(&ingress_sender, &writer_control);
    ingress_sender
        .shutdown(std::net::Shutdown::Write)
        .expect("finish ingress");
    drop(writer_control);
    let output = child.wait_with_output().expect("wait for packaged runne");
    drop(daemon_control);
    assert!(
        output.status.success(),
        "runne helper failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn send_handoff(transport: &UnixStream, control: &UnixStream) {
    let mut frame = [0_u8; 160];
    frame[..32].fill(1);
    frame[96..128].fill(2);
    let sent = send_right(transport, &IoSlice::new(&frame), control.as_raw_fd());
    assert_eq!(sent, frame.len());
}

fn send_right(transport: &UnixStream, bytes: &IoSlice<'_>, descriptor: libc::c_int) -> usize {
    #[repr(C, align(16))]
    struct AlignedControl([u8; 64]);

    let mut control = AlignedControl([0; 64]);
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as _) } as _;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!header.is_null());
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as _) as _;
        libc::CMSG_DATA(header)
            .cast::<libc::c_int>()
            .write(descriptor);
    }
    let sent = unsafe { libc::sendmsg(transport.as_raw_fd(), &message, 0) };
    assert!(
        sent >= 0,
        "sendmsg failed: {}",
        std::io::Error::last_os_error()
    );
    usize::try_from(sent).expect("nonnegative send length")
}

struct TestPackage {
    root: std::path::PathBuf,
}

impl TestPackage {
    fn new() -> Self {
        let temporary =
            fs::canonicalize(std::env::temp_dir()).expect("canonical test temporary directory");
        let root = temporary.join(format!(
            "runne-b2b2ii-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create unique test root");
        let application = root.join("Runne.app");
        let contents = application.join("Contents");
        let macos = contents.join("MacOS");
        let resources = contents.join("Resources");
        let contracts = resources.join("contracts");
        let contract = contracts.join("gocode-ui-client-2");
        fs::create_dir_all(&macos).expect("create MacOS directory");
        fs::create_dir_all(&contract).expect("create contract directory");
        for directory in [
            application.as_path(),
            contents.as_path(),
            macos.as_path(),
            resources.as_path(),
            contracts.as_path(),
            contract.as_path(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
                .expect("secure directory mode");
        }
        let current = std::env::current_exe().expect("current test executable");
        for (name, identifier) in [
            ("runne-desktop", "dev.runne.desktop"),
            ("runne", "dev.runne.writer"),
            ("runned", "dev.runne.daemon"),
        ] {
            let path = macos.join(name);
            fs::copy(&current, &path).expect("copy helper binary");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("secure executable mode");
            let status = Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-", "--identifier", identifier])
                .arg(&path)
                .status()
                .expect("codesign helper");
            assert!(status.success(), "codesign failed for {name}");
        }
        let bundle = contract.join("bundle.json");
        fs::write(&bundle, b"{\"schema\":\"gocode-ui-client-2\"}").expect("write contract");
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o644))
            .expect("secure contract mode");
        Self { root }
    }

    fn writer(&self) -> std::path::PathBuf {
        self.root.join("Runne.app/Contents/MacOS/runne")
    }

    fn daemon(&self) -> std::path::PathBuf {
        self.root.join("Runne.app/Contents/MacOS/runned")
    }
}

impl Drop for TestPackage {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove scoped test package");
    }
}
