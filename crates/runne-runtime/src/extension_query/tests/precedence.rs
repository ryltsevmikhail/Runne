use super::super::*;
use super::fixtures::*;
use MetadataQueryError::*;
// Breaks caught: reordered admission leaks owner state, treats query version as snapshot schema.
fn owner() -> ConfiguredExtensionRegistry {
    capture(&json()).unwrap()
}
fn missing(r: &mut QueryRequest) {
    r.query = Query::Get {
        key: key(ExtensionKind::Mcp, "missing"),
    };
}
#[test]
fn foreign_closed_unknown_key_is_scope_denied() {
    for closed in [false, true] {
        let o = owner();
        if closed {
            o.close(1).unwrap();
        }
        for project in [false, true] {
            for contract in [1, 2] {
                for id in ["local-tools", "missing"] {
                    let mut r = request();
                    if project {
                        let mut p = *r.context.project.as_bytes();
                        p[15] = 3;
                        r.context.project = runne_domain::id::ProjectId::from_bytes(p);
                    } else {
                        r.context.principal = runne_api::ApiPrincipalId::new("foreign").unwrap();
                    }
                    r.context.contract_version = contract;
                    r.context.runtime_generation = 0;
                    r.expected_snapshot.registration_revision = 0;
                    r.query = Query::Get {
                        key: key(ExtensionKind::Mcp, id),
                    };
                    assert_eq!(o.query(r).unwrap_err(), ScopeDenied);
                }
            }
        }
    }
}
#[test]
fn own_closed_precedes_query_version_and_bounds() {
    let o = owner();
    o.close(1).unwrap();
    let mut r = request();
    r.context.contract_version = 2;
    r.expected_snapshot.registration_revision = 0;
    assert_eq!(o.query(r).unwrap_err(), OwnerClosed);
}
#[test]
fn own_open_query_version_precedes_expected_bounds() {
    let o = owner();
    let mut r = request();
    r.context.contract_version = 2;
    r.expected_snapshot.registration_revision = 0;
    r.context.runtime_generation = 0;
    assert_eq!(o.query(r).unwrap_err(), UnsupportedContract);
}
#[test]
fn remaining_request_bounds_precede_generation() {
    let o = owner();
    for n in 0..5 {
        let mut r = request();
        r.context.runtime_generation = 2;
        match n {
            0 => r.expected_snapshot.registration_revision = 0,
            1 => r.context.owner_epoch = 0,
            2 => r.context.runtime_incarnation = [0; 16],
            3 => {
                r.query = Query::Get {
                    key: key(ExtensionKind::Mcp, ""),
                }
            }
            _ => r.context.runtime_generation = u64::MAX,
        }
        assert_eq!(o.query(r).unwrap_err(), InvalidRequest);
    }
}
#[test]
fn generation_precedes_snapshot_and_key() {
    let o = owner();
    let mut r = request();
    r.context.runtime_generation = 2;
    r.expected_snapshot.schema_version = 2;
    missing(&mut r);
    assert_eq!(o.query(r).unwrap_err(), StaleGeneration);
}
#[test]
fn expected_schema_two_is_stale_snapshot() {
    let o = owner();
    let mut r = request();
    r.expected_snapshot.schema_version = 2;
    assert_eq!(o.query(r).unwrap_err(), StaleSnapshot);
}
#[test]
fn snapshot_precedes_missing_key() {
    let o = owner();
    for n in 0..2 {
        let mut r = request();
        missing(&mut r);
        if n == 0 {
            r.expected_snapshot.registration_revision = 8;
        } else {
            r.expected_snapshot.metadata_digest = [0; 32];
        }
        assert_eq!(o.query(r).unwrap_err(), StaleSnapshot);
    }
}
#[test]
fn owner_independent_scope_syntax_is_checked_first() {
    let o = owner();
    o.close(1).unwrap();
    let mut r = request();
    r.context.project = runne_domain::id::ProjectId::from_bytes([0; 16]);
    assert_eq!(o.query(r).unwrap_err(), InvalidRequest);
    // Principal syntax cannot be forged through the existing validated domain constructor.
    assert!(runne_api::ApiPrincipalId::new("").is_err());
}
