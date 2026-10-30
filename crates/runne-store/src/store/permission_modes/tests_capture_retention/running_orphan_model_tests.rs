//! Pure vectors only. No proc, environment, filesystem or clock execution.
use super::model::{CollectionKey, ContextRecord, RootIdentity, root_name};
use std::path::Path;
use uuid::Uuid;

fn record() -> ContextRecord {
    let scenario = Uuid::parse_str("019a1830-0000-7000-8000-000000000001").unwrap();
    let identity = RootIdentity {
        device: 7,
        inode: 10,
        uid: 1000,
        gid: 1000,
        mode: 0o40700,
    };
    let mut case_identity = identity.clone();
    case_identity.inode = 11;
    ContextRecord {
        version: 1,
        collection: CollectionKey {
            source: "a".repeat(64),
            artifact: "b".repeat(64),
            nonce: "0".repeat(32),
        },
        scenario,
        collector: 2,
        supervisor: 3,
        collection_root: "/dev/shm/runne-r05-collector-abcdef".to_owned(),
        collection_identity: identity,
        case_root: format!("/dev/shm/runne-r05-case-{scenario}"),
        case_identity,
        pid_namespace: "pid:[123]".to_owned(),
        mount_namespace: "mnt:[124]".to_owned(),
        membership: "/runne-test".to_owned(),
        deadline_ns: 1,
    }
}

#[test]
fn context_roundtrip_preserves_collection_and_independent_scenario() {
    let value = record();
    value.validate();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        serde_json::from_slice::<ContextRecord>(&bytes).unwrap(),
        value
    );
    assert_eq!(value.collection.nonce, "0".repeat(32));
    // C nonce has no UUID/nonzero requirement. The case UUID has its own grammar.
    assert_ne!(value.collection.nonce, value.scenario.simple().to_string());
}

#[test]
fn collection_hex_rejects_wrong_case_width_and_nonhex() {
    for (field, bad) in [
        (0, "A".repeat(64)),
        (0, "a".repeat(63)),
        (1, "g".repeat(64)),
        (1, "b".repeat(65)),
        (2, "0".repeat(31)),
        (2, "\0".repeat(32)),
    ] {
        let mut value = record().collection;
        match field {
            0 => value.source = bad,
            1 => value.artifact = bad,
            _ => value.nonce = bad,
        }
        assert!(std::panic::catch_unwind(|| value.validate()).is_err());
    }
}

#[test]
fn context_rejects_role_root_namespace_and_version_drift() {
    let mutations: &[fn(&mut ContextRecord)] = &[
        |r| r.version = 2,
        |r| r.collector = 1,
        |r| r.supervisor = r.collector,
        |r| r.supervisor = u32::MAX,
        |r| r.case_identity.inode = r.collection_identity.inode,
        |r| r.case_identity.device += 1,
        |r| r.collection_identity.uid = 0,
        |r| r.case_identity.mode = 0o40755,
        |r| r.case_identity.inode = 0,
        |r| r.pid_namespace = "pid:[0]".to_owned(),
        |r| r.mount_namespace = "mnt:[01]".to_owned(),
        |r| r.membership = "/a/../b".to_owned(),
        |r| r.deadline_ns = 0,
        |r| r.scenario = Uuid::nil(),
        |r| r.case_root.push('x'),
    ];
    for mutation in mutations {
        let mut value = record();
        mutation(&mut value);
        assert!(std::panic::catch_unwind(|| value.validate()).is_err());
    }
}

#[test]
fn context_json_rejects_unknown_fields_at_each_level() {
    for location in ["", "collection", "collection_identity", "case_identity"] {
        let mut value = serde_json::to_value(record()).unwrap();
        let object = if location.is_empty() {
            &mut value
        } else {
            &mut value[location]
        };
        object
            .as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), true.into());
        assert!(serde_json::from_value::<ContextRecord>(value).is_err());
    }
}

#[test]
fn guest_root_spelling_is_closed_and_cannot_normalize() {
    root_name(Path::new("/dev/shm/runne-r05-case-ok"), "runne-r05-case-");
    for path in [
        "/tmp/runne-r05-case-ok",
        "/dev/shm//runne-r05-case-ok",
        "/dev/shm/./runne-r05-case-ok",
        "/dev/shm/runne-r05-case-ok/",
        "/dev/shm/runne-r05-case-",
        "/dev/shm/runne-r05-case-..",
        "/dev/shm/runne-r05-case-ok/sub",
        "/dev/shm/runne-r05-case-a b",
    ] {
        assert!(
            std::panic::catch_unwind(|| root_name(Path::new(path), "runne-r05-case-")).is_err()
        );
    }
}

#[test]
fn scenario_text_adapter_rejects_noncanonical_uuid_spelling() {
    let mut value = serde_json::to_value(record()).unwrap();
    assert!(value["scenario"].is_string());
    value["scenario"] = "019A1830-0000-7000-8000-000000000001".into();
    assert!(serde_json::from_value::<ContextRecord>(value).is_err());
}
