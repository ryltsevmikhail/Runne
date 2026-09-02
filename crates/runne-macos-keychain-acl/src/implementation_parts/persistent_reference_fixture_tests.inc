#[cfg(test)]
mod persistent_reference_fixture_tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    #[test]
    fn fixture_rejects_noncanonical_root_symlink_and_wrong_parent() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = fixture_tree(&root);
        assert!(checked(&root, None, true, false).is_ok());
        assert!(checked(&fixture.home, Some(&root), true, false).is_ok());
        assert!(checked(&fixture.keychain, Some(&root), false, false).is_ok());
        assert!(checked(&fixture.writer, Some(&root), false, true).is_ok());
        assert!(checked(&fixture.desktop, Some(&root), false, true).is_ok());
        assert!(validate_persistent_reference_fixture(
            &root,
            &fixture.home,
            &fixture.keychain,
            &fixture.writer,
            &fixture.desktop,
            PersistentReferenceProbeRole::Writer,
        )
        .is_ok());
        assert!(validate_persistent_reference_fixture(
            &root,
            &fixture.home,
            &fixture.keychain,
            &fixture.reader,
            &fixture.desktop,
            PersistentReferenceProbeRole::Reader,
        )
        .is_ok());
        assert!(validate_persistent_reference_fixture(
            &root,
            &fixture.home,
            &fixture.keychain,
            &fixture.reader,
            &fixture.desktop,
            PersistentReferenceProbeRole::Writer,
        )
        .is_err());
        assert!(validate_persistent_reference_fixture(
            &root.join("wrong-root"),
            &fixture.home,
            &fixture.keychain,
            &fixture.writer,
            &fixture.desktop,
            PersistentReferenceProbeRole::Writer,
        )
        .is_err());
        let symlink = root.join("fixture-link");
        std::os::unix::fs::symlink(&root, &symlink).unwrap();
        assert!(validate_persistent_reference_fixture(
            &symlink,
            &fixture.home,
            &fixture.keychain,
            &fixture.writer,
            &fixture.desktop,
            PersistentReferenceProbeRole::Writer,
        )
        .is_err());
        assert!(validate_persistent_reference_fixture(
            &root,
            &fixture.home,
            &fixture.keychain,
            &fixture.writer,
            &fixture.reader,
            PersistentReferenceProbeRole::Writer,
        )
        .is_err());
    }

    #[test]
    fn owner_mode_and_channel_predicates_fail_closed() {
        let uid = unsafe { libc::geteuid() };
        assert!(owner_only(uid, u32::from(libc::S_IFREG | 0o500), false));
        assert!(!owner_only(
            uid.wrapping_add(1),
            u32::from(libc::S_IFREG | 0o500),
            false,
        ));
        assert!(!owner_only(uid, u32::from(libc::S_IFREG | 0o540), false));
        assert!(!owner_only(uid, u32::from(libc::S_IFLNK | 0o700), true));
        let identity = (uid, unsafe { libc::getegid() });
        assert!(channel_is_bound(true, identity, true));
        assert!(!channel_is_bound(false, identity, true));
        assert!(!channel_is_bound(true, (uid.wrapping_add(1), identity.1), true));
        assert!(!channel_is_bound(true, identity, false));
    }

    struct FixtureTree {
        home: std::path::PathBuf,
        keychain: std::path::PathBuf,
        desktop: std::path::PathBuf,
        writer: std::path::PathBuf,
        reader: std::path::PathBuf,
    }

    fn fixture_tree(root: &std::path::Path) -> FixtureTree {
        let home = root.join("home");
        let keychains = home.join("Library/Keychains");
        let macos = root.join("Runne.app/Contents/MacOS");
        for directory in [
            &home,
            &home.join("Library"),
            &keychains,
            &root.join("Runne.app"),
            &root.join("Runne.app/Contents"),
            &macos,
        ] {
            fs::create_dir_all(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let keychain = keychains.join("runne-ci.keychain-db");
        let desktop = macos.join("runne-desktop");
        let writer = macos.join("runne");
        let reader = macos.join("runned");
        for file in [&keychain, &desktop, &writer, &reader] {
            fs::write(file, []).unwrap();
            let mode = if file == &keychain { 0o600 } else { 0o500 };
            fs::set_permissions(file, fs::Permissions::from_mode(mode)).unwrap();
        }
        assert_eq!(fs::metadata(&writer).unwrap().uid(), unsafe { libc::geteuid() });
        FixtureTree {
            home,
            keychain,
            desktop,
            writer,
            reader,
        }
    }
}
