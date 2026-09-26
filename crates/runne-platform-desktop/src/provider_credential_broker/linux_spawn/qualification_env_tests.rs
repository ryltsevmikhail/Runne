use super::{SessionBusAddress, opted_in_fixture_root, plan};
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use std::os::unix::fs::PermissionsExt as _;

const CHILD: &str = "RUNNE_QUALIFICATION_SPAWN_ENV_CHILD";
const MARKER: &str = "RUNNE_QUALIFICATION_SPAWN_ENV_MARKER";

#[test]
fn qualification_only_control_spawn_reads_validated_fixture_root() {
    if std::env::var_os(CHILD).is_some() {
        let root = opted_in_fixture_root()
            .expect("qualification env validates")
            .expect("qualification env forwarded");
        let spec = VerifiedWriterLaunchSpec::new(
            VerifiedWriterArtifact::new("/bundle/runne".into(), [1; 32], [2; 32]).unwrap(),
        );
        let spawn = plan::build_plan(
            &spec,
            &SessionBusAddress("/run/user/1/bus".into()),
            10,
            11,
            12,
            None,
            Some(&root),
        )
        .expect("production spawn plan accepts validated root");
        let forwarded = spawn.environment.iter().any(|entry| {
            entry
                .to_string_lossy()
                .starts_with("RUNNE_D1_1B_POST_DELETE_KILL_FIXTURE_ROOT=")
        });
        assert!(forwarded);
        std::fs::write(std::env::var_os(MARKER).expect("child marker path"), b"ok").unwrap();
        return;
    }

    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("fixture");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let marker = parent.path().join("spawn-plan.marker");
    let child_test = "provider_credential_broker::unix_daemon::linux_spawn::qualification_env_tests::qualification_only_control_spawn_reads_validated_fixture_root";
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", child_test])
        .env(CHILD, "1")
        .env(MARKER, &marker)
        .env("RUNNE_D1_1B_POST_DELETE_KILL_FIXTURE_ROOT", &root)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "qualification child failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        marker.is_file(),
        "qualification-only child test ran: {}",
        String::from_utf8_lossy(&child.stdout)
    );
}
