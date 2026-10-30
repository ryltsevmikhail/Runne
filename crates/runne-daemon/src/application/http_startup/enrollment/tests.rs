use super::mounted;

#[test]
fn qualified_release_without_control_fails_closed() {
    assert!(mounted(true, true, true, false).is_err());
    assert!(!mounted(false, true, true, false).unwrap());
    assert!(!mounted(true, true, false, false).unwrap());
}

#[test]
fn bare_cli_never_mounts_the_protected_enrollment_router() {
    assert!(!mounted(false, true, true, true).unwrap());
    assert!(!mounted(false, true, true, false).unwrap());
}

#[test]
fn only_a_protected_qualified_release_with_control_mounts_enrollment() {
    assert!(mounted(true, true, true, true).unwrap());
}
