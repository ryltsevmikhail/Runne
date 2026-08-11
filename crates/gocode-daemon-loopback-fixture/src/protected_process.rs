/// Runs one argument-free fixture daemon over the inherited protected channel.
#[allow(clippy::result_unit_err)]
pub fn run_protected_fixture() -> Result<(), ()> {
    if std::env::args_os().count() != 1 {
        return Err(());
    }
    gocode_daemon::protected_activation::test_support::run_loopback_inherited_fixture()
        .map_err(|_| ())
}
