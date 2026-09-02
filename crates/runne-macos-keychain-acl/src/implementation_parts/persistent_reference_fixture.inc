use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

const FIXTURE_ROOT: &str = "RUNNE_SLICE_E_FIXTURE_ROOT";
const LOCAL_ENROLLMENT: &str = "RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST";
const INNER_CASE: &str = "RUNNE_SLICE_E_INNER_CASE";

/// Exact role that may enter the local persistent-reference feasibility lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentReferenceProbeRole {
    /// The package-owned credential writer.
    Writer,
    /// The package-owned reader daemon.
    Reader,
}

/// Canonical package paths validated before a probe opens its Keychain.
pub struct PersistentReferenceFixture {
    keychain: PathBuf,
    writer: PathBuf,
    reader: PathBuf,
}

impl PersistentReferenceFixture {
    /// Returns the one explicitly owned disposable Keychain path.
    #[must_use]
    pub fn keychain(&self) -> &Path {
        &self.keychain
    }

    /// Returns the canonical package writer role.
    #[must_use]
    pub fn writer(&self) -> &Path {
        &self.writer
    }

    /// Returns the canonical package reader role.
    #[must_use]
    pub fn reader(&self) -> &Path {
        &self.reader
    }
}

/// Validates local opt-in, fixture ownership, exact role and package parent.
///
/// # Errors
///
/// Returns a closed error before any Keychain call unless every local-only
/// precondition is satisfied by the inherited process environment and paths.
pub fn current_persistent_reference_fixture(
    role: PersistentReferenceProbeRole,
    selector: &str,
) -> Result<PersistentReferenceFixture, KeychainAclError> {
    if std::env::var_os(LOCAL_ENROLLMENT).as_deref() != Some("1".as_ref())
        || std::env::var_os(INNER_CASE).as_deref() != Some(selector.as_ref())
    {
        return Err(KeychainAclError::AccessDenied);
    }
    let root = PathBuf::from(std::env::var_os(FIXTURE_ROOT).ok_or(KeychainAclError::AccessDenied)?);
    let home = PathBuf::from(std::env::var_os("HOME").ok_or(KeychainAclError::AccessDenied)?);
    let keychain = PathBuf::from(
        std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN").ok_or(KeychainAclError::AccessDenied)?,
    );
    let current = std::fs::canonicalize(std::env::current_exe().map_err(|_| KeychainAclError::AccessDenied)?)
        .map_err(|_| KeychainAclError::AccessDenied)?;
    let parent = parent_executable()?;
    validate_persistent_reference_fixture(&root, &home, &keychain, &current, &parent, role)
}

/// Rejects a non-socket, cross-user, cross-session or non-parent inherited FD.
///
/// # Errors
///
/// Returns a closed error unless stdin is the same-session Unix socket held by
/// the validated package desktop parent and a same-uid/gid peer.
pub fn validate_persistent_reference_parent_channel() -> Result<(), KeychainAclError> {
    let fd = std::io::stdin().as_raw_fd();
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stdin is live and `metadata` is valid output storage.
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
        return Err(KeychainAclError::AccessDenied);
    }
    // SAFETY: fstat initialized metadata after the zero return above.
    let metadata = unsafe { metadata.assume_init() };
    let mut peer_identity = (libc::uid_t::MAX, libc::gid_t::MAX);
    // SAFETY: stdin is a valid descriptor; peer outputs are writable.
    if unsafe { libc::getpeereid(fd, &raw mut peer_identity.0, &raw mut peer_identity.1) } != 0 {
        return Err(KeychainAclError::AccessDenied);
    }
    let parent = unsafe { libc::getppid() };
    let session_matches = parent > 1
        // SAFETY: getsid has no additional pointer or ownership preconditions.
        && unsafe { libc::getsid(0) } == unsafe { libc::getsid(parent) };
    if channel_is_bound(
        metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK,
        peer_identity,
        session_matches,
    ) {
        Ok(())
    } else {
        Err(KeychainAclError::AccessDenied)
    }
}

fn validate_persistent_reference_fixture(
    root: &Path,
    home: &Path,
    keychain: &Path,
    current: &Path,
    parent: &Path,
    role: PersistentReferenceProbeRole,
) -> Result<PersistentReferenceFixture, KeychainAclError> {
    let root = checked(root, None, true, false)?;
    let expected_home = root.join("home");
    let expected_keychains = expected_home.join("Library/Keychains");
    let application = root.join("Runne.app");
    let contents = application.join("Contents");
    let macos = contents.join("MacOS");
    for directory in [&expected_home, &expected_home.join("Library"), &expected_keychains, &application, &contents, &macos] {
        checked(directory, Some(&root), true, false)?;
    }
    let expected_keychain = expected_keychains.join("runne-ci.keychain-db");
    let desktop = macos.join("runne-desktop");
    let writer = macos.join("runne");
    let reader = macos.join("runned");
    checked(&expected_keychain, Some(&root), false, false)?;
    for role in [&desktop, &writer, &reader] {
        checked(role, Some(&root), false, true)?;
    }
    let expected_current = match role {
        PersistentReferenceProbeRole::Writer => &writer,
        PersistentReferenceProbeRole::Reader => &reader,
    };
    if home != expected_home
        || keychain != expected_keychain
        || canonical(current)? != *expected_current
        || canonical(parent)? != desktop
    {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(PersistentReferenceFixture {
        keychain: expected_keychain,
        writer,
        reader,
    })
}

fn checked(
    path: &Path,
    root: Option<&Path>,
    directory: bool,
    executable: bool,
) -> Result<PathBuf, KeychainAclError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| KeychainAclError::AccessDenied)?;
    let canonical = canonical(path)?;
    if canonical != path
        || root.is_some_and(|root| !canonical.starts_with(root))
        || !owner_only(metadata.uid(), metadata.mode(), directory)
        || (executable && metadata.mode() & 0o100 == 0)
    {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(canonical)
}

fn canonical(path: &Path) -> Result<PathBuf, KeychainAclError> {
    std::fs::canonicalize(path).map_err(|_| KeychainAclError::AccessDenied)
}

fn owner_only(uid: libc::uid_t, mode: u32, directory: bool) -> bool {
    uid == unsafe { libc::geteuid() }
        && mode.trailing_zeros() >= 6
        && mode & u32::from(libc::S_IFMT)
            == if directory {
                u32::from(libc::S_IFDIR)
            } else {
                u32::from(libc::S_IFREG)
            }
}

fn channel_is_bound(
    socket: bool,
    peer_identity: (libc::uid_t, libc::gid_t),
    session_matches: bool,
) -> bool {
    socket
        && peer_identity.0 == unsafe { libc::geteuid() }
        && peer_identity.1 == unsafe { libc::getegid() }
        && session_matches
}

fn parent_executable() -> Result<PathBuf, KeychainAclError> {
    let mut bytes = [0_u8; 4096];
    // SAFETY: pid is live and bytes is a writable fixed-capacity buffer.
    let length = unsafe {
        libc::proc_pidpath(
            libc::getppid(),
            bytes.as_mut_ptr().cast(),
            u32::try_from(bytes.len()).map_err(|_| KeychainAclError::AccessDenied)?,
        )
    };
    if length <= 0 || usize::try_from(length).map_or(true, |length| length >= bytes.len()) {
        return Err(KeychainAclError::AccessDenied);
    }
    let length = usize::try_from(length).map_err(|_| KeychainAclError::AccessDenied)?;
    let path = std::ffi::OsString::from_vec(bytes[..length].to_vec());
    canonical(Path::new(&path))
}
