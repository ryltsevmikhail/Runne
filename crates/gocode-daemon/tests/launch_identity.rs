use gocode_daemon::launch_identity::LaunchIdentity;
use gocode_store::schema::{
    ConnectionMode, apply_migrations, next_launch_generation, open_managed_connection,
};
use tempfile::tempdir;

#[test]
fn launches_are_unique_and_generation_survives_database_reopen() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("event-log.sqlite");
    let first_generation = {
        let connection = open_managed_connection(&database, ConnectionMode::Writer).unwrap();
        apply_migrations(&connection).unwrap();
        next_launch_generation(&connection).unwrap()
    };
    let second_generation = {
        let connection = open_managed_connection(&database, ConnectionMode::Writer).unwrap();
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
    assert!(!profile.contains("PRIVATE KEY"));
    assert!(!profile.contains("BEGIN"));
}

#[test]
fn corrupt_launch_generations_are_never_rewritten() {
    for value in ["zero", "0", "18446744073709551615"] {
        let directory = tempdir().unwrap();
        let database = directory.path().join("event-log.sqlite");
        let connection = open_managed_connection(&database, ConnectionMode::Writer).unwrap();
        apply_migrations(&connection).unwrap();
        connection
            .execute(
                "INSERT INTO _daemon_info (key, value) VALUES ('launch_generation', ?1)",
                [value],
            )
            .unwrap();
        assert!(next_launch_generation(&connection).is_err());
        let current: String = connection
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current, value);
    }
}
