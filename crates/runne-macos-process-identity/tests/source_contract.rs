#[cfg(target_os = "macos")]
#[test]
fn current_process_identity_is_opaque_and_stable() {
    use std::num::NonZeroU32;

    use runne_macos_process_identity::MacOsProcessStartIdentity;

    let pid = NonZeroU32::new(std::process::id()).unwrap();
    let first = MacOsProcessStartIdentity::observe(pid).unwrap();
    let second = MacOsProcessStartIdentity::observe(pid).unwrap();

    assert_ne!(first.digest(), [0; 32]);
    assert_eq!(first.digest(), second.digest());
    assert_eq!(
        format!("{first:?}"),
        "MacOsProcessStartIdentity(<kernel-observed>)"
    );
}
