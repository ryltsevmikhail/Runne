#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use runne_macos_keychain_acl::ExactKeychainAccess;

static NEXT_TEMP_ARTIFACT: AtomicU64 = AtomicU64::new(0);

struct TempExecutable {
    directory: PathBuf,
    raw_path: PathBuf,
}

impl TempExecutable {
    fn create() -> Self {
        let directory = unique_temp_directory();
        let raw_path = directory.join("trusted-application");
        let artifact = Self {
            directory,
            raw_path,
        };
        set_owner_private(&artifact.directory);
        let source = std::env::current_exe().expect("current test binary path");
        let permissions = fs::metadata(&source)
            .expect("current test binary metadata")
            .permissions();
        fs::copy(&source, &artifact.raw_path).expect("copy test binary");
        fs::set_permissions(&artifact.raw_path, permissions)
            .expect("preserve test binary permissions");
        artifact
    }
}

impl Drop for TempExecutable {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.raw_path);
        let _ = fs::remove_dir(&self.directory);
    }
}

fn unique_temp_directory() -> PathBuf {
    let canonical_root =
        fs::canonicalize(std::env::temp_dir()).expect("canonical macOS temporary directory");
    let temporary_root = Path::new("/").join(
        canonical_root
            .strip_prefix("/private")
            .expect("macOS temporary directory below /private"),
    );
    let process_id = std::process::id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    for _ in 0..128 {
        let counter = NEXT_TEMP_ARTIFACT.fetch_add(1, Ordering::Relaxed);
        let directory =
            temporary_root.join(format!("runne-acl-{process_id}-{timestamp}-{counter}"));
        match fs::create_dir(&directory) {
            Ok(()) => return directory,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create temporary directory: {error}"),
        }
    }
    panic!("unable to create a unique temporary directory");
}

fn set_owner_private(directory: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("set temporary directory permissions");
    }
}

#[test]
fn private_prefix_alias_and_canonical_path_have_identical_digest() {
    let executable = TempExecutable::create();
    let canonical =
        fs::canonicalize(&executable.raw_path).expect("canonical copied test binary path");

    assert!(!executable.raw_path.starts_with("/private/"));
    assert_eq!(
        canonical,
        Path::new("/private").join(executable.raw_path.strip_prefix("/").unwrap())
    );

    let raw_access = ExactKeychainAccess::new(&executable.raw_path, &executable.raw_path).unwrap();
    let canonical_access = ExactKeychainAccess::new(&canonical, &canonical).unwrap();

    assert_eq!(raw_access.digest(), canonical_access.digest());
}
