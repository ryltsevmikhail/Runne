use super::{assertions::rows, fixture::Fixture};
use crate::schema;
use rusqlite::{Connection, TransactionBehavior, types::Value};

fn catalog(c: &Connection) -> Vec<Vec<Value>> {
    rows(
        c,
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name",
        [],
    )
}
fn identity(c: &Connection) -> Vec<Vec<Value>> {
    rows(c, "SELECT * FROM project_trust_schema ORDER BY id", [])
}
fn trust(c: &Connection, f: &Fixture) -> Vec<Vec<Value>> {
    rows(
        c,
        "SELECT * FROM project_trust WHERE project_id=?1",
        [f.trust_id().as_bytes().as_slice()],
    )
}
fn policy(c: &Connection, f: &Fixture) -> Vec<Vec<Value>> {
    rows(
        c,
        "SELECT policy_version,fs_read,fs_create,fs_write,fs_delete,process_start,network_use
        FROM managed_effect_policies WHERE project_id=?1",
        [f.trust_id().as_bytes().as_slice()],
    )
}
fn version(c: &Connection) -> i64 {
    c.query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

pub(super) fn cut(f: &Fixture, delete: bool) {
    let (authority, epoch) = f.trust.registration_identity();
    assert_eq!(hex::encode(authority), f.scope.runtime_authority_id.0);
    assert_ne!(epoch, 0);
    let path = f
        .root
        .path()
        .join("runtime/daemon/trust.sqlite.project-trust");
    let (mut injector, observed_epoch) =
        schema::reopen_managed_project_trust_sidecar(&path, authority)
            .expect("injection setup failure is not selected GO denial");
    assert_eq!(observed_epoch, epoch);
    injector.verify_retained_identity().unwrap();
    assert_eq!(version(&injector), 3);
    let original_catalog = catalog(&injector);
    let original_identity = identity(&injector);
    let original_trust = trust(&injector, f);
    assert_eq!(original_trust.len(), 1);
    let record: (i64, i64, i64) = injector
        .query_row(
            "SELECT status,managed_deny_mask,revision FROM project_trust WHERE project_id=?1",
            [f.trust_id().as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(record, (2, 0, 1));
    let expected: Vec<Vec<Value>> = vec![
        vec![1, 0, 0, 0, 0, 0, 0]
            .into_iter()
            .map(Value::Integer)
            .collect(),
    ];
    assert_eq!(policy(&injector, f), expected);
    {
        let tx = injector
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(catalog(&tx), original_catalog);
        assert_eq!(identity(&tx), original_identity);
        assert_eq!(trust(&tx, f), original_trust);
        assert_eq!(policy(&tx, f), expected);
        if delete {
            assert_eq!(
                tx.execute(
                    "DELETE FROM managed_effect_policies WHERE project_id = ?1",
                    rusqlite::params![f.trust_id().as_bytes().as_slice()]
                )
                .unwrap(),
                1
            );
        }
        tx.commit().unwrap();
    }
    injector.verify_retained_identity().unwrap();
    assert_eq!(version(&injector), 3);
    assert_eq!(catalog(&injector), original_catalog);
    assert_eq!(identity(&injector), original_identity);
    assert_eq!(trust(&injector, f), original_trust);
    let expected_after = if delete { Vec::new() } else { expected };
    assert_eq!(policy(&injector, f), expected_after);
    let (validator, validated_epoch) =
        schema::reopen_managed_project_trust_sidecar(&path, authority).unwrap();
    assert_eq!(validated_epoch, epoch);
    validator.verify_retained_identity().unwrap();
    assert!(validator.same_database_identity(&injector).unwrap());
    assert_eq!(version(&validator), 3);
    assert_eq!(catalog(&validator), original_catalog);
    assert_eq!(identity(&validator), original_identity);
    assert_eq!(trust(&validator, f), original_trust);
    assert_eq!(policy(&validator, f), expected_after);
    drop(validator);
    drop(injector); // No injector/transaction/lease may survive into public GO.
}
