//! Test-only Linux Pair cycle, using the exact production claim/effect source.
//! Only the store backend is fake. Never staged or shipped; no real credentials.
#![allow(dead_code)]
use std::io::Write as _;
use std::os::fd::AsFd as _;
#[path = "../src/cli/provider_credential_broker/channel.rs"]
mod channel;
#[path = "../src/cli/provider_credential_broker/claim.rs"]
mod claim;
#[path = "../src/cli/provider_credential_broker/effect.rs"]
mod effect;
#[path = "../src/cli/provider_credential_broker/pair.rs"]
mod pair;
#[path = "../src/cli/provider_credential_broker/run.rs"]
mod run;
#[path = "../src/cli/provider_credential_broker/secret.rs"]
mod secret;
#[path = "../tests/writer_fixture_support/mod.rs"]
mod support;
#[path = "../src/cli/provider_credential_broker/writer_fd_sweep.rs"]
mod writer_fd_sweep;

#[derive(Debug)]
pub enum CliError {
    CredentialOperation,
}

fn main() {
    let secret = channel::InheritedSecretInputSlot::inspect().unwrap();
    let retained = secret.validated_descriptor_for_sweep().unwrap();
    writer_fd_sweep::close_inherited_descriptors_except(
        writer_fd_sweep::enumerate_proc_fds,
        retained,
    )
    .unwrap();
    // A copied fixture binary may opt into a shared fake directory next to
    // itself. This code exists only in the example, never the shipped CLI.
    let fake_root = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixture-store");
    let _store = if fake_root.is_dir() {
        runne_secure_store::install_test_source(Box::new(
            runne_secure_store::DirectoryFakeSource::new(&fake_root).unwrap(),
        ))
    } else {
        runne_secure_store::install_test_source(Box::new(
            runne_secure_store::CountingFakeSource::unlocked(),
        ))
    };
    let session = runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession
        ::receive_linux_authenticated_writer().unwrap();
    let effect_succeeded = run::run_linux_authenticated_writer(session, secret).is_ok();
    let peer = rustix::net::sockopt::socket_peercred(std::io::stdin()).unwrap();
    let daemon_path = std::path::PathBuf::from(format!("/proc/{}/exe", peer.pid.as_raw_pid()));
    let access = runne_secure_store::ProviderCredentialAccessPolicy::new(
        std::path::Path::new("/proc/self/exe"),
        &daemon_path,
    )
    .unwrap();
    let (_, readback, _, _) =
        runne_secure_store::NativeProviderCredentialReaders::new(access).into_parts();
    let observed = readback
        .readback_exact_version(
            runne_secure_store::ExactVersionReadback::new(support::pair_command()).unwrap(),
        )
        .unwrap();
    assert_eq!(observed.present(), effect_succeeded);
    assert_ne!(observed.binding().as_bytes(), [0; 32]);
    let mut control = std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
    control
        .write_all(if effect_succeeded {
            b"readback"
        } else {
            b"noeffect"
        })
        .unwrap();
}
