fn replace_bound_runtime_authority(database_path: &Path) {
    let connection = Connection::open(database_path).expect("open desktop database");
    let key: String = connection
        .query_row(
            "SELECT key FROM settings WHERE key LIKE 'runtime.conversation.project.%'",
            [],
            |row| row.get(0),
        )
        .expect("conversation reference key");
    let serialized: String = connection
        .query_row("SELECT value FROM settings WHERE key = ?1", [&key], |row| {
            row.get(0)
        })
        .expect("conversation reference");
    let mut reference: serde_json::Value =
        serde_json::from_str(&serialized).expect("conversation reference JSON");
    reference["runtimeAuthority"] = serde_json::json!("018f2e3a700070008000000000000099");
    connection
        .execute(
            "UPDATE settings SET value = ?1 WHERE key = ?2",
            [
                serde_json::to_string(&reference).expect("conversation reference JSON"),
                key,
            ],
        )
        .expect("replace bound authority");
}

fn delete_first_daemon_event(database_path: &Path) {
    let connection = Connection::open(database_path).expect("open daemon database");
    assert_eq!(
        connection
            .execute("DELETE FROM events WHERE global_position = 1", [])
            .expect("delete retained event"),
        1
    );
}

fn revoke_live_replay_epoch(database_path: &Path) {
    let connection = Connection::open(database_path).expect("open daemon database");
    assert_eq!(
        connection
            .execute(
                "UPDATE _replay_subscriptions
                 SET authorization_epoch = authorization_epoch + 1
                 WHERE state = 'live'",
                [],
            )
            .expect("revoke live replay epoch"),
        1
    );
}

#[allow(clippy::type_complexity)]
fn promote_conversation_event_to_unknown_schema(database_path: &Path, sequence: i64) {
    let connection = Connection::open(database_path).expect("open daemon database");
    let row: (
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = connection
        .query_row(
            "
            SELECT event_id, aggregate_id, sequence, global_position, timestamp,
                   sensitivity, causation_id, command_id, idempotency_key, actor, payload
            FROM events
            WHERE aggregate_type = 2 AND sequence = ?1
            ",
            [sequence],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .expect("conversation event");
    let event_id = EventId::from_bytes(fixed_16(&row.0));
    let conversation_id = ConversationId::from_bytes(fixed_16(&row.1));
    let causation_id = row
        .6
        .as_ref()
        .map(|value| EventId::from_bytes(fixed_16(value)));
    let command_id = CommandId::from_bytes(fixed_16(&row.7));
    let idempotency_key =
        IdempotencyKey::new(String::from_utf8(row.8.clone()).expect("idempotency key UTF-8"))
            .expect("idempotency key");
    let actor = Actor::new(String::from_utf8(row.9.clone()).expect("actor UTF-8"))
        .expect("canonical actor");
    let sensitivity = match row.5 {
        0 => Sensitivity::Public,
        1 => Sensitivity::Internal,
        2 => Sensitivity::Sensitive,
        _ => panic!("invalid sensitivity"),
    };
    let payload = ConversationEventCodec
        .decode(&row.10)
        .expect("conversation event payload");
    let envelope = EventEnvelope::from_parts(
        event_id,
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        causation_id,
        command_id,
        idempotency_key,
        2,
        actor,
        sensitivity,
        payload,
        u64::try_from(row.2).expect("event sequence"),
        Timestamp::from_unix_micros(row.4),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest = compute_integrity_digest_v2_with_global_position(&envelope, row.3, &row.10)
        .expect("unknown-schema integrity digest");
    assert_eq!(
        connection
            .execute(
                "UPDATE events
                 SET schema_version = 2, integrity_digest = ?1
                 WHERE aggregate_type = 2 AND sequence = ?2",
                rusqlite::params![digest.as_bytes().as_slice(), sequence],
            )
            .expect("promote event schema"),
        1
    );
}

fn fixed_16(value: &[u8]) -> [u8; 16] {
    value.try_into().expect("16-byte identity")
}

fn wait_for_closed_replay_session(database_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Connection::open(database_path)
            .expect("open daemon database")
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM _replay_subscriptions WHERE state = 'closed'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .expect("read replay session state")
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "disconnected replay session did not close"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn closed_replay_progress(database_path: &Path) -> (Option<i64>, Option<i64>) {
    Connection::open(database_path)
        .expect("open daemon database")
        .query_row(
            "
            SELECT last_acked_position, last_delivered_position
            FROM _replay_subscriptions
            WHERE state = 'closed'
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("closed replay progress")
}

fn required_child_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).expect("required child path"))
}

fn wait_for_profile(profile_path: &Path, minimum_generation: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(bytes) = std::fs::read(profile_path)
            && let Ok(profile) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && profile["launchGeneration"].as_u64().unwrap_or_default() >= minimum_generation
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "daemon profile publication timeout"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn profile_value(profile_path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(profile_path).expect("read profile"))
        .expect("profile JSON")
}

fn endpoint_address(profile: &serde_json::Value) -> SocketAddr {
    profile["endpoint"]
        .as_str()
        .and_then(|endpoint| endpoint.strip_prefix("https://"))
        .expect("HTTPS loopback endpoint")
        .parse()
        .expect("socket address")
}

async fn connect_identity(profile_path: &Path) -> ObservedSessionIdentity {
    let client = LocalRuntimeProfile::load(profile_path)
        .expect("strict profile v2")
        .connect(Duration::from_secs(5))
        .await
        .expect("peer-authenticated session");
    let session = client.session_info();
    ObservedSessionIdentity {
        authority: session.authority_id.clone(),
        principal: session.principal_id.clone(),
        lineage: session.event_log_lineage_id.clone(),
        instance: session.daemon_instance_id.clone(),
        generation: session.launch_generation,
        session: session.session_id.clone(),
    }
}

fn install_ack_failure_after_inclusive_duplicate(database_path: &Path) {
    let connection = Connection::open(database_path).expect("open daemon database");
    connection
        .busy_timeout(Duration::from_secs(5))
        .expect("daemon database busy timeout");
    connection
        .execute_batch(
            "
            CREATE TRIGGER fail_replay_ack_after_duplicate
            BEFORE UPDATE OF last_acked_position ON _replay_subscriptions
            WHEN OLD.last_acked_position IS NOT NULL
             AND NEW.last_acked_position > OLD.last_acked_position
            BEGIN
                SELECT RAISE(FAIL, 'forced unacknowledged replay');
            END;
            ",
        )
        .expect("install replay acknowledgement fault");
}

fn remove_ack_failure(database_path: &Path) {
    Connection::open(database_path)
        .expect("open daemon database")
        .execute_batch("DROP TRIGGER fail_replay_ack_after_duplicate;")
        .expect("remove replay acknowledgement fault");
}
