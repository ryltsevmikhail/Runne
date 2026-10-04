pub(super) async fn assert_denied_before_provider(
    core: &runne_app_core::AppCore,
    project: i64,
    denied_canaries: &[String],
    runtime_root: &std::path::Path,
) {
    for denied_canary in denied_canaries {
        let denied = core
            .send_project_message(project, denied_canary)
            .await
            .expect_err("registered frozen canary must be denied before provider effect");
        assert!(
            matches!(
                denied,
                runne_app_core::AppCoreError::ProhibitedInputRejected
            ),
            "unexpected hostile-canary result: {denied:?}"
        );
        assert!(!format!("{denied:?}").contains(denied_canary));
        assert!(
            !runtime_root
                .join("fixture-provider-connection-count")
                .exists(),
            "denied provider input must not open the loopback transport"
        );
    }
}

pub(super) fn sha256(path: &std::path::Path) -> [u8; 32] {
    use sha2::Digest as _;
    let contents = std::fs::read(path).expect("read controlled runtime executable for hash");
    sha2::Sha256::digest(contents).into()
}

pub(super) fn sha256_hex(path: &std::path::Path) -> String {
    hex::encode(sha256(path))
}

pub(super) fn copy_controlled_runtime() -> super::owner_private::ControlledExecutable {
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_runned"));
    let source_digest = sha256_hex(source);
    let executable = super::owner_private::ControlledExecutable::copy_with_writer_from(source);
    let copy_digest = sha256_hex(executable.path());
    eprintln!("INFO: T1 daemon SHA-256 source={source_digest} controlled-copy={copy_digest}");
    executable
}
