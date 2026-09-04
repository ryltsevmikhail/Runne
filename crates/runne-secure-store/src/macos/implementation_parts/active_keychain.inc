fn active_keychain() -> Result<SecKeychain, ()> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(path) = explicit_test_keychain(
        std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN"),
        std::env::var_os("HOME"),
    )? {
        return SecKeychain::open(path).map_err(|_| ());
    }
    SecKeychain::default().map_err(|_| ())
}

#[cfg(any(test, feature = "test-support"))]
fn explicit_test_keychain(
    path: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<Option<std::ffi::OsString>, ()> {
    let Some(path) = path else {
        // Unit tests must never fall through to the user's default Keychain.
        // Non-test builds retain the existing production/test-support behavior.
        return if cfg!(test) { Err(()) } else { Ok(None) };
    };
    let expected = std::path::PathBuf::from(home.ok_or(())?)
        .join("Library/Keychains/runne-ci.keychain-db");
    if std::path::Path::new(&path) != expected {
        return Err(());
    }
    Ok(Some(path))
}

#[cfg(test)]
mod keychain_selection_tests {
    use super::explicit_test_keychain;

    #[test]
    fn unit_tests_require_explicit_keychain_before_native_access() {
        assert_eq!(explicit_test_keychain(None, Some("/private/test".into())), Err(()));
    }

    #[test]
    fn explicit_keychain_requires_exact_test_home_path() {
        let path = "/private/test/Library/Keychains/runne-ci.keychain-db";
        assert_eq!(explicit_test_keychain(Some(path.into()), Some("/private/test".into())),
            Ok(Some(path.into())));
        assert_eq!(explicit_test_keychain(Some(path.into()), None), Err(()));
        assert_eq!(explicit_test_keychain(Some("/private/test/login.keychain-db".into()),
            Some("/private/test".into())), Err(()));
    }
}
