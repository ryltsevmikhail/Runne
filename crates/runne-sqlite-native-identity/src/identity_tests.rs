#[cfg(unix)]
use std::sync::Mutex;

#[cfg(unix)]
static VFS_REGISTRY: Mutex<()> = Mutex::new(());

#[test]
fn unix_abi_proof_and_public_checks_precede_private_prefix_cast() {
    let source = include_str!("lib.rs");
    let abi = source.find("if !exact_sqlite()").expect("ABI proof");
    let witness = source
        .find("let (trusted, file) = trusted_unix_connection(connection)")
        .expect("trusted connection witness");
    let private = source
        .find("file.cast::<UnixFilePrefix>")
        .expect("private cast");
    let trusted_builtin = source
        .find("let trusted_builtin = trusted_vfs::trusted_builtin_vfs()")
        .expect("trusted builtin");
    let public_vfs = source
        .find("let vfs = public_unix_vfs(connection, trusted_builtin)")
        .expect("public VFS check");
    let file = source
        .find("SQLITE_FCNTL_FILE_POINTER")
        .expect("file pointer");
    let methods = source
        .find("let methods = unsafe { (*file).pMethods }")
        .expect("public methods");
    assert!(abi < witness && witness < private);
    assert!(trusted_builtin < public_vfs && public_vfs < file && file < methods);
}

#[cfg(unix)]
#[test]
fn same_name_custom_vfs_is_rejected_before_private_prefix_access() {
    let _registry = VFS_REGISTRY.lock().expect("registry lock");
    let trusted = super::trusted_vfs::trusted_builtin_vfs().expect("trusted VFS");
    // SAFETY: copied only for this serialized negative test and unregistered before drop.
    let mut custom = Box::new(unsafe { std::ptr::read(trusted) });
    custom.pNext = std::ptr::null_mut();
    custom.zName = c"unix".as_ptr();
    // SAFETY: no connection uses the builtin VFS in this serialized test.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_vfs_unregister(trusted) },
        rusqlite::ffi::SQLITE_OK
    );
    // SAFETY: the test-owned VFS remains allocated until after connection drop.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_vfs_register(&raw mut *custom, 1) },
        rusqlite::ffi::SQLITE_OK
    );
    // SAFETY: this test owns the current default VFS registration until restoration below.
    let custom_pointer = std::ptr::from_mut::<rusqlite::ffi::sqlite3_vfs>(&mut *custom);
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_vfs_find(std::ptr::null()) },
        custom_pointer
    );
    // SAFETY: same-name lookup must resolve the custom VFS, not the trusted capture.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_vfs_find(c"unix".as_ptr()) },
        custom_pointer
    );
    super::PRIVATE_PREFIX_ATTEMPTS.store(0, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("identity-custom-vfs-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let connection = rusqlite::Connection::open_with_flags_and_vfs(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        "unix",
    )
    .expect("custom VFS connection");
    assert_eq!(
        super::opened_database_identity(&connection),
        Err(super::IdentityError)
    );
    assert_eq!(
        super::PRIVATE_PREFIX_ATTEMPTS.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    drop(connection);
    // SAFETY: no connection uses the test VFS after the drop above.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_vfs_unregister(&raw mut *custom) },
        rusqlite::ffi::SQLITE_OK
    );
    // SAFETY: restores the exact immutable builtin VFS captured at process initialization.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_vfs_register(trusted, 1) },
        rusqlite::ffi::SQLITE_OK
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn vfs_registration_is_test_only_and_confined_to_this_audited_shim() {
    let lib_source = include_str!("lib.rs");
    assert!(!lib_source.contains("sqlite3_vfs_register"));
    assert!(!lib_source.contains("sqlite3_vfs_unregister"));
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    for production_root in [root.join("crates"), root.join("apps")] {
        for source in rust_sources(&production_root) {
            let relative = source.strip_prefix(root).expect("relative source");
            let content = std::fs::read_to_string(&source).expect("read source");
            if content.contains("sqlite3_vfs_register")
                || content.contains("sqlite3_vfs_unregister")
            {
                assert!(
                    relative
                        == std::path::Path::new(
                            "crates/runne-sqlite-native-identity/src/identity_tests.rs"
                        ),
                    "unapproved VFS mutation in {}",
                    relative.display()
                );
            }
        }
    }
}

#[test]
fn trusted_capture_requires_the_exact_builtin_default_before_private_access() {
    let source = include_str!("trusted_vfs.rs");
    let initialize = source
        .find("sqlite3_initialize")
        .expect("SQLite initialization");
    let default = source
        .find("sqlite3_vfs_find(std::ptr::null())")
        .expect("default VFS");
    let named = source
        .find("sqlite3_vfs_find(c\"unix\"")
        .expect("named VFS");
    let equality = source
        .find("builtin == named_unix")
        .expect("pointer equality");
    let immutable = source.find("compare_exchange").expect("immutable capture");
    assert!(initialize < default && default < named && named < equality && equality < immutable);
}

fn rust_sources(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(root).expect("read crate root") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            sources.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    sources
}
