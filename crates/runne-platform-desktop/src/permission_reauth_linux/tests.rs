use super::policy;

#[test]
#[ignore = "read-only current-host PAM policy qualification; no authentication is attempted"]
fn current_arch_system_auth_policy_is_reviewed_and_safe() {
    policy::qualify().expect("current host matches the reviewed Arch system-auth policy");
}

#[test]
fn unknown_stacks_modules_and_options_are_rejected() {
    let system_auth = policy::test_profile_fixture();
    assert!(policy::test_profile_is_reviewed(&system_auth));
    for changed in [
        String::from_utf8_lossy(&system_auth).replace(
            "pam_unix.so try_first_pass nullok",
            "pam_unix.so try_first_pass nullok custom_unknown_option",
        ),
        String::from_utf8_lossy(&system_auth)
            .replace("auth required pam_env.so", "auth include common-auth"),
        String::from_utf8_lossy(&system_auth).replace(
            "account required pam_time.so",
            "account substack other-account",
        ),
    ] {
        assert!(!policy::test_profile_is_reviewed(changed.as_bytes()));
    }
}

#[test]
fn relevant_configuration_semantics_and_fingerprints_are_exact() {
    let faillock = b"# reviewed defaults\ndeny = 10\n";
    assert!(policy::test_config_is_reviewed(0, faillock));
    assert!(!policy::test_config_is_reviewed(0, b"deny = 1\n"));
    assert!(!policy::test_config_is_reviewed(1, b"PATH DEFAULT=/tmp\n"));
    assert!(!policy::test_config_is_reviewed(
        2,
        b"login;tty*;*;Al0000-2400\n"
    ));
    assert!(!policy::test_config_is_reviewed(3, b"PATH=/tmp\n"));
    assert!(policy::test_same_fingerprint([1; 32], [1; 32]));
    assert!(!policy::test_same_fingerprint([1; 32], [2; 32]));
}

#[test]
fn user_writable_or_non_root_paths_are_rejected() {
    assert!(policy::test_secure_mode(0, 0o644));
    assert!(!policy::test_secure_mode(1000, 0o644));
    assert!(!policy::test_secure_mode(0, 0o666));
    assert!(!policy::test_secure_mode(0, 0o775));
}

#[test]
fn active_line_normalization_preserves_options_and_order() {
    assert_eq!(
        policy::test_active_lines(b"# comment\nauth  required pam_unix.so nullok\n\n")
            .expect("UTF-8 config"),
        ["auth required pam_unix.so nullok"]
    );
    assert!(policy::test_active_lines(&[0xff]).is_err());
}
