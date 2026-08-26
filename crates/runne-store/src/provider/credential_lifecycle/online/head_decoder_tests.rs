use runne_provider::{CredentialLifecycleError, CredentialVersionRef, ProviderId};
use rusqlite::{Connection, params, types::Value};

use super::head::load_head;

#[test]
fn strict_head_decoder_rejects_malformed_active_refs() {
    let provider = ProviderId::new("openai").unwrap();
    let foreign = CredentialVersionRef::new(ProviderId::new("anthropic").unwrap(), 1).unwrap();
    for (version, digest) in [
        (Value::Integer(1), Value::Null),
        (Value::Null, Value::Blob(vec![1; 32])),
        (Value::Integer(0), Value::Blob(vec![1; 32])),
        (Value::Integer(1), Value::Blob(vec![1; 31])),
        (Value::Integer(1), Value::Text("digest-text".into())),
        (Value::Text("1".into()), Value::Blob(vec![1; 32])),
        (
            Value::Integer(1),
            Value::Blob(foreign.ref_digest().to_vec()),
        ),
    ] {
        let connection = head_connection(version, digest);
        assert!(matches!(
            load_head(&connection, &provider),
            Err(CredentialLifecycleError::CorruptState)
        ));
    }
}

fn head_connection(active_version: Value, active_digest: Value) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE provider_credential_authority_heads (
                 provider_id,
                 lifecycle_revision,
                 credential_fence,
                 readiness_revision,
                 next_credential_version,
                 active_credential_version,
                 active_ref_digest,
                 hard_fence_disposition,
                 observed_at_high_water
             )",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_authority_heads VALUES
             ('openai', 1, 1, 1, 2, ?1, ?2, NULL, 0)",
            params![active_version, active_digest],
        )
        .unwrap();
    connection
}
