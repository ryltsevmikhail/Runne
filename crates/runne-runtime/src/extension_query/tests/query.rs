use super::super::*;
use super::fixtures::*;
use MetadataQueryError::*;

#[test]
fn kind_filter_preserves_scope_and_snapshot() {
    let o = capture(&json()).unwrap();
    for kind in [ExtensionKind::Mcp, ExtensionKind::Plugin] {
        let mut r = request();
        r.query = Query::List { kind: Some(kind) };
        let reply = o.query(r).unwrap();
        assert_eq!(reply.records.len(), 2);
        assert!(reply.records.iter().all(|r| r.key().kind == kind));
        assert_eq!(reply.scope, scope());
        assert_eq!(reply.snapshot, version());
        assert_eq!(reply.owner_epoch, 1);
    }
}
#[test]
fn owned_missing_key_is_not_found() {
    let o = capture(&json()).unwrap();
    let mut r = request();
    r.query = Query::Get {
        key: key(ExtensionKind::Mcp, "missing"),
    };
    assert_eq!(o.query(r).unwrap_err(), NotFound);
}
#[test]
fn foreign_principal_is_denied_before_lookup() {
    let o = capture(&json()).unwrap();
    for id in ["local-tools", "missing"] {
        let mut r = request();
        r.context.principal = runne_api::ApiPrincipalId::new("other").unwrap();
        r.query = Query::Get {
            key: key(ExtensionKind::Mcp, id),
        };
        assert_eq!(o.query(r).unwrap_err(), ScopeDenied);
    }
}
#[test]
fn foreign_project_is_denied_before_lookup() {
    let o = capture(&json()).unwrap();
    let mut r = request();
    r.context.project = runne_domain::id::ProjectId::from_bytes([0x77; 16]);
    assert_eq!(o.query(r).unwrap_err(), InvalidRequest);
    r = request();
    let mut p = *r.context.project.as_bytes();
    p[15] = 3;
    r.context.project = runne_domain::id::ProjectId::from_bytes(p);
    assert_eq!(o.query(r).unwrap_err(), ScopeDenied);
}
#[test]
fn explicit_empty_config_is_not_missing_source() {
    let text = document("");
    let mut e = expected();
    e.version.metadata_digest =
        hex::decode("6b71e5aa870411ec4afa3425b553efd1f6078f5f6e11ce8e9303279947ae4241")
            .unwrap()
            .try_into()
            .unwrap();
    let v = e.version.clone();
    let o = ConfiguredExtensionRegistry::capture(file(text.as_bytes()), e).unwrap();
    let mut r = request();
    r.expected_snapshot = v;
    assert!(o.query(r).unwrap().records.is_empty());
    reject("", InvalidSnapshot);
}
#[test]
fn capture_survives_source_replacement_without_reread() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    let old = directory.path().join("old");
    std::fs::write(&path, json()).unwrap();
    let o = ConfiguredExtensionRegistry::capture(std::fs::File::open(&path).unwrap(), expected())
        .unwrap();
    assert!(!old.exists());
    std::fs::rename(&path, &old).unwrap();
    std::fs::write(&path, b"malformed replacement").unwrap();
    std::fs::write(&old, b"overwrite inode").unwrap();
    assert_eq!(o.query(request()).unwrap().records.len(), 4);
}
#[test]
fn reopen_preserves_metadata_not_runtime_binding() {
    let a = capture(&json()).unwrap();
    let mut e = expected();
    e.scope.runtime_incarnation = [2; 16];
    let b = ConfiguredExtensionRegistry::capture(file(json().as_bytes()), e).unwrap();
    assert_eq!(b.query(request()).unwrap_err(), StaleGeneration);
    let mut r = request();
    r.context.runtime_incarnation = [2; 16];
    assert_eq!(
        a.query(request()).unwrap().records,
        b.query(r).unwrap().records
    );
}

// Break caught: reject-all capture or empty/default projection instead of real records.
#[test]
fn file_backed_list_and_get_are_exact() {
    let owner = capture(&json()).expect("valid file must publish owner");
    let reply = owner.query(request()).unwrap();
    assert_eq!(reply.records.len(), 4);
    assert_eq!(
        reply
            .records
            .iter()
            .map(|r| r.key().id.0)
            .collect::<Vec<_>>(),
        ["local-tools", "remote-tools", "formatter", "linter"]
    );
    assert_eq!(reply.snapshot.metadata_digest, super::vectors::DIGEST);
    assert_eq!(reply.scope, scope());
    let mut req = request();
    req.query = Query::Get {
        key: key(ExtensionKind::Plugin, "formatter"),
    };
    assert_eq!(
        owner.query(req).unwrap().records,
        vec![reply.records[2].clone()]
    );
}
