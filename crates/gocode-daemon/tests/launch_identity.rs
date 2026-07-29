use gocode_daemon::launch_identity::LaunchIdentity;
use gocode_store::schema::{apply_migrations, next_launch_generation, open_with_pragmas};
use tempfile::tempdir;

#[test]
fn launches_are_unique_and_generation_survives_database_reopen() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("event-log.sqlite");
    let first_generation = {
        let connection = open_with_pragmas(database.to_str().unwrap()).unwrap();
        apply_migrations(&connection).unwrap();
        next_launch_generation(&connection).unwrap()
    };
    let second_generation = {
        let connection = open_with_pragmas(database.to_str().unwrap()).unwrap();
        apply_migrations(&connection).unwrap();
        next_launch_generation(&connection).unwrap()
    };
    let first = LaunchIdentity::generate(first_generation).unwrap();
    let second = LaunchIdentity::generate(second_generation).unwrap();

    assert_ne!(first.certificate_sha256(), second.certificate_sha256());
    assert_ne!(
        first.bootstrap_secret_marker(),
        second.bootstrap_secret_marker()
    );
    assert_ne!(first.daemon_instance_id(), second.daemon_instance_id());
    assert_eq!(second.launch_generation(), first.launch_generation() + 1);
    assert_eq!(first.subject_alt_name_ips(), ["127.0.0.1", "::1"]);
}

#[test]
fn launch_profile_never_contains_private_key_bytes() {
    let identity = LaunchIdentity::generate(1).unwrap();
    let profile = identity.profile_certificate_der_base64();
    let profile_bytes = profile.as_bytes();

    assert!(
        !profile_bytes
            .windows(32)
            .any(|part| part == identity.private_key_marker()),
        "certificate profile data must not contain private-key bytes"
    );
}
