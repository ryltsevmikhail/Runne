use std::io::{Read as _, Write as _};
use std::path::Path;

use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};

use super::RetainedWriterProcess as _;

#[test]
fn protected_lifecycle_relay_size_matches_provider_codec_exactly() {
    assert_eq!(
        runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES,
        runne_provider::CredentialSecretRelayFrameCodec::BYTES
    );
}

#[test]
fn pair_spawn_inherits_bootstrap_on_stdin_and_separate_pipe_on_fd3() {
    let fixture = compile_descriptor_fixture();
    let spec = launch_spec(&fixture);
    let image = super::macos_writer_admission::test_retained_writer_image(&fixture).unwrap();
    let (transport, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let pair = super::macos_secret_pipe::prepare_pair_secret_pipe().unwrap();

    let (mut process, secret_writer) =
        super::unix_daemon_macos::spawn_macos_prepared_writer(&spec, &image, transport, Some(pair))
            .unwrap();

    let mut descriptor_state = [0_u8; 2];
    peer.read_exact(&mut descriptor_state).unwrap();
    assert_eq!(descriptor_state, [1, 1]);
    assert!(secret_writer.is_some());
    peer.write_all(&[1]).unwrap();
    process.reap_retained_child().unwrap();
}

#[test]
fn non_pair_spawn_does_not_create_or_inherit_fd3() {
    let _parent_fd3_canary = ensure_parent_fd3_open();
    assert!(std::fs::metadata("/dev/fd/3").is_ok());
    let fixture = compile_descriptor_fixture();
    let spec = launch_spec(&fixture);
    let image = super::macos_writer_admission::test_retained_writer_image(&fixture).unwrap();
    let (transport, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();

    let (mut process, secret_writer) =
        super::unix_daemon_macos::spawn_macos_prepared_writer(&spec, &image, transport, None)
            .unwrap();

    let mut descriptor_state = [0_u8; 2];
    peer.read_exact(&mut descriptor_state).unwrap();
    assert_eq!(descriptor_state, [1, 0]);
    assert!(secret_writer.is_none());
    peer.write_all(&[1]).unwrap();
    process.reap_retained_child().unwrap();
}

#[test]
fn non_pair_spawn_actions_explicitly_close_fd3() {
    let source = include_str!("unix_daemon_macos.rs");
    assert!(source.contains("None => actions.add_close(3)"));
}

#[test]
fn provider_root_does_not_export_raw_authenticated_relay_sealer() {
    let provider_root = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../runne-provider/src/lib.rs"
    ));
    let ordinary_exports = provider_root
        .split_once("pub use credential::{")
        .unwrap()
        .1
        .split_once("};")
        .unwrap()
        .0;
    assert!(
        !ordinary_exports.contains("AuthenticatedCredentialSecretRelaySealer"),
        "raw key/channel relay construction must not be part of the provider root API"
    );
}

#[test]
fn raw_relay_hook_has_exactly_one_authenticated_platform_call_site() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let needle = concat!(
        "AuthenticatedCredentialSecretRelaySealer",
        "::from_authenticated_rendezvous("
    );
    let mut matches = Vec::new();
    for relative in ["crates", "apps"] {
        collect_production_source_matches(&workspace.join(relative), needle, &mut matches);
    }
    assert_eq!(
        matches.len(),
        1,
        "unexpected raw relay hook sites: {matches:?}"
    );
    assert!(matches[0].ends_with("provider_credential_broker/daemon_rendezvous.rs"));
}

fn collect_production_source_matches(
    directory: &Path,
    needle: &str,
    matches: &mut Vec<std::path::PathBuf>,
) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            let ignored = path.file_name().is_some_and(|name| {
                matches!(
                    name.to_str(),
                    Some(
                        "target"
                            | "vendor"
                            | "generated"
                            | "tests"
                            | "test-support"
                            | "test_support"
                    )
                )
            });
            if !ignored {
                collect_production_source_matches(&path, needle, matches);
            }
        } else if is_production_rust_source(&path)
            && std::fs::read_to_string(&path).unwrap().contains(needle)
        {
            matches.push(path);
        }
    }
}

fn is_production_rust_source(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "rs")
        && path.file_stem().is_some_and(|stem| {
            let stem = stem.to_string_lossy();
            stem != "tests" && !stem.starts_with("test_") && !stem.ends_with("_test")
        })
}

fn launch_spec(path: &Path) -> VerifiedWriterLaunchSpec {
    VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(path.to_path_buf(), [1; 32], [2; 32]).unwrap(),
    )
}

fn compile_descriptor_fixture() -> std::path::PathBuf {
    let directory = tempfile::tempdir().unwrap().keep();
    let source = directory.join("descriptor_fixture.c");
    let executable = directory.join("descriptor_fixture");
    std::fs::write(
        &source,
        br"
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    struct stat bootstrap;
    struct stat secret;
    unsigned char observed[2] = {0, 0};
    if (fstat(STDIN_FILENO, &bootstrap) == 0 && S_ISSOCK(bootstrap.st_mode)) {
        observed[0] = 1;
    }
    errno = 0;
    if (fstat(3, &secret) == 0 && S_ISFIFO(secret.st_mode)) {
        observed[1] = 1;
    } else if (errno != EBADF) {
        return 11;
    }
    if (write(STDIN_FILENO, observed, sizeof(observed)) != sizeof(observed)) {
        return 12;
    }
    unsigned char gate = 0;
    return read(STDIN_FILENO, &gate, 1) == 1 ? 0 : 13;
}
",
    )
    .unwrap();
    let output = std::process::Command::new("/usr/bin/clang")
        .args(["-Wall", "-Werror", "-o"])
        .arg(&executable)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

fn ensure_parent_fd3_open() -> Vec<std::fs::File> {
    let mut held = Vec::new();
    while std::fs::metadata("/dev/fd/3").is_err() {
        held.push(std::fs::File::open("/dev/null").unwrap());
    }
    held
}
