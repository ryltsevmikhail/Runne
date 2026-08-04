use std::collections::BTreeMap;

use super::{EventRow, hex};

pub(super) fn snapshot(row: &EventRow) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for (key, value) in [
        ("event_id", hex(&row.event_id)),
        ("aggregate_id", hex(&row.aggregate_id)),
        ("command_id", hex(&row.command_id)),
        ("idempotency_key", hex(&row.idempotency_key)),
        ("actor", hex(&row.actor)),
        ("payload", hex(&row.payload)),
        ("integrity_digest", hex(&row.integrity_digest)),
        ("correlation_id", hex(&row.correlation_id)),
    ] {
        values.insert(key.into(), value);
    }
    values.insert(
        "causation_id".into(),
        row.causation_id
            .as_ref()
            .map_or("null".into(), |value| hex(value)),
    );
    for (key, value) in [
        ("aggregate_type", row.aggregate_type),
        ("sequence", row.sequence),
        ("global_position", row.global_position),
        ("timestamp", row.timestamp),
        ("sensitivity", row.sensitivity),
        ("schema_version", row.schema_version),
        ("correlation_type", row.correlation_type),
        ("integrity_profile", row.integrity_profile),
    ] {
        values.insert(key.into(), value.to_string());
    }
    values
}
