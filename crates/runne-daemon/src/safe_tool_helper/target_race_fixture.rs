use std::{
    ffi::CStr,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    thread,
    time::{Duration, Instant},
};

const BARRIER_DIRECTORY: &CStr = c".runne-test-approved-target-race";
const ENTERED: &CStr = c"create.entered";
const RELEASE: &CStr = c"create.release";
const DEADLINE: Duration = Duration::from_millis(1_750);

pub(super) fn after_create_before_write(root: &File) -> Result<(), ()> {
    if !trusted_fixture() {
        return Ok(());
    }
    let directory = openat(
        root.as_raw_fd(),
        BARRIER_DIRECTORY,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )?;
    if !private_directory(&directory) {
        return Err(());
    }
    let entered = openat(
        directory.as_raw_fd(),
        ENTERED,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        0o600,
    )?;
    if !private_regular(&entered) {
        return Err(());
    }
    write_all(&entered, b"entered\n")?;
    entered.sync_all().map_err(|_| ())?;
    wait_for_release(&directory)
}

fn trusted_fixture() -> bool {
    std::env::var("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref() == Ok("1")
        && std::env::var("RUNNE_TEST_T1_APPROVED_TARGET_RACE").as_deref() == Ok("1")
        && std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref()
            == Ok("approved-target-create-race")
}

fn wait_for_release(directory: &File) -> Result<(), ()> {
    let deadline = Instant::now() + DEADLINE;
    loop {
        match openat(
            directory.as_raw_fd(),
            RELEASE,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        ) {
            Ok(release) if private_regular(&release) => return Ok(()),
            Ok(_) => return Err(()),
            Err(()) if last_error_is_missing() => {}
            Err(()) => return Err(()),
        }
        if Instant::now() >= deadline {
            return Err(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn openat(directory: RawFd, name: &CStr, flags: i32, mode: libc::mode_t) -> Result<File, ()> {
    let fd = unsafe { libc::openat(directory, name.as_ptr(), flags | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn private_directory(file: &File) -> bool {
    let Ok(metadata) = metadata(file) else {
        return false;
    };
    metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
        && metadata.st_uid == unsafe { libc::geteuid() }
        && metadata.st_mode & 0o022 == 0
}

fn private_regular(file: &File) -> bool {
    let Ok(metadata) = metadata(file) else {
        return false;
    };
    metadata.st_mode & libc::S_IFMT == libc::S_IFREG
        && metadata.st_uid == unsafe { libc::geteuid() }
        && metadata.st_mode & 0o022 == 0
        && metadata.st_nlink == 1
}

fn metadata(file: &File) -> Result<libc::stat, ()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(());
    }
    Ok(unsafe { metadata.assume_init() })
}

fn write_all(file: &File, bytes: &[u8]) -> Result<(), ()> {
    use io::Write as _;
    file.try_clone()
        .map_err(|_| ())?
        .write_all(bytes)
        .map_err(|_| ())
}

fn last_error_is_missing() -> bool {
    io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
}
