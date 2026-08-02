use std::path::Path;

use gocode_macos_keychain_acl::ExactKeychainAccess;

#[test]
fn var_alias_and_private_var_canonical_path_have_identical_digest() {
    let current = std::env::current_exe().expect("current test binary path");
    let canonical = std::fs::canonicalize(&current).expect("canonical test binary path");
    let alias = canonical
        .strip_prefix("/private")
        .map(|relative| Path::new("/").join(relative))
        .expect("current test binary must be in /private/var");

    assert!(alias.starts_with("/var/"));
    let canonical_access = ExactKeychainAccess::new(&canonical, &canonical).unwrap();
    let alias_access = ExactKeychainAccess::new(&alias, &canonical).unwrap();

    assert_eq!(alias_access.digest(), canonical_access.digest());
}
