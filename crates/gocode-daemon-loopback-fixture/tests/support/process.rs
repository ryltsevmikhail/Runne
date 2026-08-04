#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use gocode_api::ProviderActivationBindingV1;
use gocode_platform_desktop::{
    BundledRuntimeProcessStatus, DevelopmentBundledRuntimeLauncher,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeProcess,
};
use gocode_runtime_client::AuthenticatedRuntimeClient;

pub fn executable(name: &str, fixture_root: &Path) -> PathBuf {
    let source = match name {
        "activation_process" => PathBuf::from(env!("CARGO_BIN_EXE_activation_process")),
        "recovery_process" => PathBuf::from(env!("CARGO_BIN_EXE_recovery_process")),
        _ => panic!("unknown fixture executable"),
    };
    let destination = fixture_root.join(name);

    #[cfg(unix)]
    std::fs::set_permissions(fixture_root, std::fs::Permissions::from_mode(0o700))
        .expect("make fixture executable root owner-private");
    std::fs::copy(&source, &destination).expect("copy fixture executable into owner-private root");
    #[cfg(unix)]
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))
        .expect("make copied fixture executable owner-private");

    destination
}

fn openai_spec(executable: &Path, runtime_root: &Path) -> ProtectedBundledRuntimeLaunchSpec {
    ProtectedBundledRuntimeLaunchSpec::new(executable, runtime_root)
        .expect("owner-private protected fixture spec")
        .with_provider_activation(ProviderActivationBindingV1::openai_responses_text_v1())
}

pub async fn protected_client(
    process: &mut ProtectedBundledRuntimeProcess,
) -> AuthenticatedRuntimeClient {
    let profile = process
        .take_runtime_profile()
        .expect("one-time protected profile");
    let client = profile
        .connect(Duration::from_secs(10))
        .await
        .expect("authenticated protected runtime client");
    assert!(process.matches_client(&client));
    client
}

pub fn stop(mut process: ProtectedBundledRuntimeProcess) {
    process
        .request_graceful_stop()
        .expect("authenticated fixture shutdown");
    assert_eq!(
        process
            .wait_for_exit(Duration::from_secs(10))
            .expect("reap owned fixture child"),
        BundledRuntimeProcessStatus::Exited
    );
}

pub fn launch(executable: &Path, root: &Path) -> ProtectedBundledRuntimeProcess {
    DevelopmentBundledRuntimeLauncher::new()
        .launch(&openai_spec(executable, root))
        .expect("protected OpenAI V2 fixture launch")
}
