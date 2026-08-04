use fixture_readers::{v2_digest_for_first_v1_event, FixtureValidationError};
use rusqlite::{params, Connection};

type TamperCase = (&'static str, Box<dyn Fn(&std::path::Path)>);

#[test]
fn unknown_profile_is_rejected_fail_closed() {
    let (_directory, path, _) = copied_fixture("event-integrity-v1.sqlite");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA ignore_check_constraints = ON;").unwrap();
    connection.execute("UPDATE events SET integrity_profile = 99", []).unwrap();
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    assert_eq!(validate_events(&path, 1), Err(FixtureValidationError::UnknownProfile));
}

#[test]
fn payload_digest_and_wrong_domain_digest_tampering_are_rejected() {
    let cases: [TamperCase; 3] = [
        ("payload", Box::new(|path| { let connection = Connection::open(path).unwrap(); connection.execute("UPDATE events SET payload = ?1", params![vec![0_u8]]).unwrap(); connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap(); })),
        ("digest", Box::new(|path| { let connection = Connection::open(path).unwrap(); connection.execute("UPDATE events SET integrity_digest = ?1", params![vec![0_u8; 32]]).unwrap(); connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap(); })),
        ("domain", Box::new(|path| { let digest = v2_digest_for_first_v1_event(path).unwrap(); let connection = Connection::open(path).unwrap(); connection.execute("UPDATE events SET integrity_digest = ?1", params![digest.as_slice()]).unwrap(); connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap(); })),
    ];
    for (name, tamper) in cases {
        let (_directory, path, _) = copied_fixture("event-integrity-v1.sqlite");
        tamper(&path);
        assert_eq!(validate_events(&path, 1), Err(FixtureValidationError::Corrupt), "{name}");
    }
}
