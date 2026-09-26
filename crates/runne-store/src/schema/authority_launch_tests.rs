use super::*;

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("CREATE TABLE _daemon_info (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .unwrap();
    connection
}

#[test]
fn reserved_generations_are_unique_and_only_the_current_value_validates() {
    let connection = connection();
    assert_eq!(
        reserve_launch_generation_for_prelude(&connection).unwrap(),
        1
    );
    assert_eq!(
        reserve_launch_generation_for_prelude(&connection).unwrap(),
        2
    );
    assert!(validate_reserved_launch_generation(&connection, 2).is_ok());
    for invalid in [0, 1, 3] {
        assert!(validate_reserved_launch_generation(&connection, invalid).is_err());
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "2"
    );
    connection
        .execute(
            "UPDATE _daemon_info SET value = '9' WHERE key = 'launch_generation'",
            [],
        )
        .unwrap();
    assert_eq!(
        reserve_launch_generation_for_prelude(&connection).unwrap(),
        10
    );
    assert!(validate_reserved_launch_generation(&connection, 10).is_ok());
}

#[test]
fn corrupt_and_overflowed_generations_fail_closed_without_rewrite() {
    let connection = connection();
    connection
        .execute(
            "INSERT INTO _daemon_info VALUES ('launch_generation', '00')",
            [],
        )
        .unwrap();
    assert!(validate_reserved_launch_generation(&connection, 1).is_err());
    assert!(reserve_launch_generation_for_prelude(&connection).is_err());
    connection
        .execute("UPDATE _daemon_info SET value = ?1", [u64::MAX.to_string()])
        .unwrap();
    assert!(reserve_launch_generation_for_prelude(&connection).is_err());
    assert_eq!(
        connection
            .query_row("SELECT value FROM _daemon_info", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        u64::MAX.to_string()
    );
}

#[test]
fn unconsumed_validation_rejects_consumed_current_reservation() {
    let connection = connection();
    let reserved = reserve_launch_generation_for_prelude(&connection).unwrap();
    assert!(validate_unconsumed_reserved_launch_generation(&connection, reserved).is_ok());
    consume_reserved_launch_generation(&connection, reserved).unwrap();

    // Consumption leaves the canonical counter unchanged.
    assert!(validate_reserved_launch_generation(&connection, reserved).is_ok());
    assert!(validate_unconsumed_reserved_launch_generation(&connection, reserved).is_err());
}
