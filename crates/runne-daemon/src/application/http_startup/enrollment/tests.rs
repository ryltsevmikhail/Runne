use super::mounted;

#[test]
fn qualified_release_without_control_fails_closed() {
    assert!(mounted(true, true, true, false).is_err());
    assert!(!mounted(false, true, true, false).unwrap());
    assert!(!mounted(true, true, false, false).unwrap());
}
