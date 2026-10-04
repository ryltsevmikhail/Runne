#[cfg(all(
    feature = "test-support",
    feature = "desktop-protected",
    target_os = "linux"
))]
use std::path::Path;
#[cfg(all(
    feature = "test-support",
    feature = "desktop-protected",
    target_os = "linux"
))]
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(super) enum Point {
    BeforeRelease,
    AfterExit,
    AfterDurableTerminal,
}

impl Point {
    #[cfg(all(
        feature = "test-support",
        feature = "desktop-protected",
        target_os = "linux"
    ))]
    const fn mode(self) -> &'static str {
        match self {
            Self::BeforeRelease => "pre-release",
            Self::AfterExit => "after-exit",
            Self::AfterDurableTerminal => "after-terminal",
        }
    }

    #[cfg(all(
        feature = "test-support",
        feature = "desktop-protected",
        target_os = "linux"
    ))]
    const fn file_stem(self) -> &'static str {
        match self {
            Self::BeforeRelease => "pre-release",
            Self::AfterExit => "after-exit",
            Self::AfterDurableTerminal => "after-terminal",
        }
    }
}

pub(super) fn pause_at(point: Point) -> Result<(), ()> {
    #[cfg(not(all(
        feature = "test-support",
        feature = "desktop-protected",
        target_os = "linux"
    )))]
    {
        let _ = point;
        return Ok(());
    }
    #[cfg(all(
        feature = "test-support",
        feature = "desktop-protected",
        target_os = "linux"
    ))]
    pause_at_test_support(point)
}

#[cfg(all(
    feature = "test-support",
    feature = "desktop-protected",
    target_os = "linux"
))]
fn pause_at_test_support(point: Point) -> Result<(), ()> {
    if std::env::var_os("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return Ok(());
    }
    if std::env::var("RUNNE_TEST_LOCAL_WORKER_BARRIER")
        .ok()
        .as_deref()
        != Some(point.mode())
    {
        return Ok(());
    }
    let directory = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR").ok_or(())?;
    let directory = Path::new(&directory);
    let metadata = std::fs::symlink_metadata(directory).map_err(|_| ())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(());
        }
    }
    let entered = directory.join(format!("{}.entered", point.file_stem()));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(entered)
        .map_err(|_| ())?;
    let release = directory.join(format!("{}.release", point.file_stem()));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::symlink_metadata(&release) {
            Ok(found) if found.is_file() && !found.file_type().is_symlink() => return Ok(()),
            Ok(_) => return Err(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }
        if Instant::now() >= deadline {
            return Err(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
