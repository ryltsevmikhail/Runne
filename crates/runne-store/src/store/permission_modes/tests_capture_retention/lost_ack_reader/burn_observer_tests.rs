//! Authored before implementation. Raw private SQL primitives only; NOTRUN.
//! No managed opener, isolation, C custody, native or protocol qualification.
use super::*;
use super::super::{capture_core,Limits,terminal_tests};
#[path="burn_observer_fixture.rs"]
mod fixture;
fn burn(n:u8)->[u8;16] {let mut b=[n;16];b[6]=0x70;b[8]=0x80;b}
fn facts()->OriginalFacts<'static> {
    let e=fixture::expected();
    OriginalFacts {authority:[42;16],lineage:
        "01010101-0101-7101-8101-010101010101".parse().unwrap(),
        intent:terminal_tests::intent(),terminal:terminal_tests::expected(),
        ownership:Context {invocation:e.invocation,area:e.area,owner:e.owner,
            generation:e.generation,node:e.node,epoch:e.epoch,
            assignment_lease:e.assignment_lease,occupation_lease:e.occupation_lease,
            claim_command:e.claim_command,claim_scope:e.claim_scope,claim_key:e.claim_key,
            claim_fingerprint:e.claim_fingerprint,claim_version:e.claim_version,
            admitted:e.admitted,started:e.started,conversation:e.conversation,
            workspace:e.workspace,command_digest:e.command_digest,
            attempt_stdout:e.attempt_stdout,attempt_stderr:e.attempt_stderr}}
}
fn final_cut(c:&mut Connection,s:&Seal<'_>)->Result<()> {
    let f=&s.original;let e=f.ownership.expected(s.burn,s.burned_at);
    capture_core::capture(c,Limits::fixture(),Some(&f.intent),Some(&f.terminal),
        Some(&e),Some(s)).map(|_|())
}
#[test] fn actual_dynamic_burn_and_time_are_retained() {
    for (id,time) in [(burn(2),37),(burn(3),901)] {
        let mut c=fixture::pre(id,time);let s=observe_connection(&mut c,facts()).unwrap();
        assert_eq!(s.burn,id);assert_eq!(s.burned_at,time);
        fixture::finish(&c);assert!(final_cut(&mut c,&s).is_ok());
        assert!(c.is_autocommit());
    }
}
#[test] fn missing_burn_and_already_terminal_refuse() {
    for sql in ["DELETE FROM x2_permission_spent",
        "INSERT INTO x2_permission_terminal SELECT * FROM saved_terminal",
        "INSERT INTO taskrun_terminal_settlement_receipts SELECT * FROM saved_settlement",
        "INSERT INTO events SELECT * FROM saved_events"] {
        let mut positive=fixture::pre(burn(2),37);
        assert!(observe_connection(&mut positive,facts()).is_ok());
        let mut c=fixture::pre(burn(2),37);
        c.execute_batch(&format!("PRAGMA query_only=OFF;{sql};PRAGMA query_only=ON")).unwrap();
        assert!(observe_connection(&mut c,facts()).is_err());assert!(c.is_autocommit());
    }
}
#[test] fn duplicates_storage_classes_and_domains_refuse() {
    for sql in ["INSERT INTO x2_permission_spent SELECT * FROM x2_permission_spent",
        "UPDATE x2_permission_spent SET burn_id=zeroblob(16)",
        "UPDATE x2_permission_spent SET burn_id=zeroblob(15)",
        "UPDATE x2_permission_spent SET burn_id=CAST(burn_id AS TEXT)",
        "UPDATE x2_permission_spent SET burned_at=37.0",
        "UPDATE x2_permission_spent SET burned_at=0",
        "UPDATE x2_permission_spent SET invocation_id=zeroblob(16)",
        "UPDATE taskrun_local_command_attempts SET state='completed'",
        "UPDATE taskrun_local_command_attempts SET exit_code=0",
        "UPDATE taskrun_local_command_attempts SET fence=2.0",
        "INSERT INTO _authority SELECT * FROM _authority",
        "UPDATE _authority SET authority_id=CAST(authority_id AS TEXT)",
        "INSERT INTO _daemon_info SELECT * FROM _daemon_info",
        "UPDATE _daemon_info SET value=CAST(value AS BLOB)",
        "ALTER TABLE x2_permission_spent RENAME TO bad_spent; CREATE VIEW x2_permission_spent AS SELECT * FROM bad_spent"] {
        let mut positive=fixture::pre(burn(2),37);
        assert!(observe_connection(&mut positive,facts()).is_ok());
        let mut c=fixture::pre(burn(2),37);
        c.execute_batch(&format!("PRAGMA query_only=OFF;{sql};PRAGMA query_only=ON")).unwrap();
        assert!(observe_connection(&mut c,facts()).is_err(),"{sql}");
    }
}
#[test] fn reverse_invocation_and_burn_collisions_refuse() {
    for keep_invocation in [false,true] {
        let mut positive=fixture::pre(burn(2),37);
        assert!(observe_connection(&mut positive,facts()).is_ok());
        let mut c=fixture::pre(burn(2),37);
        c.execute_batch("PRAGMA query_only=OFF; INSERT INTO x2_permission_spent
            SELECT zeroblob(16),zeroblob(16),binding_digest,invocation_id,area_identity,
            owner_id,owner_generation,burn_id,burned_at FROM x2_permission_spent").unwrap();
        let col=if keep_invocation {"burn_id"}else{"invocation_id"};
        c.execute_batch(&format!("UPDATE x2_permission_spent SET {col}=zeroblob(16)
            WHERE taskrun_id=zeroblob(16);PRAGMA query_only=ON")).unwrap();
        assert!(observe_connection(&mut c,facts()).is_err());
    }
}
#[test] fn final_same_transaction_spent_authority_lineage_drift_refuses() {
    for sql in ["UPDATE x2_permission_spent SET burned_at=38",
        "UPDATE x2_permission_spent SET burn_id=zeroblob(16)",
        "DELETE FROM x2_permission_spent",
        "UPDATE _authority SET authority_id=zeroblob(16)",
        "DELETE FROM _daemon_info"] {
        let mut positive=fixture::pre(burn(2),37);
        let s=observe_connection(&mut positive,facts()).unwrap();fixture::finish(&positive);
        assert!(final_cut(&mut positive,&s).is_ok());
        let mut c=fixture::pre(burn(2),37);let s=observe_connection(&mut c,facts()).unwrap();
        fixture::finish(&c);
        c.execute_batch(&format!("PRAGMA query_only=OFF;{sql};PRAGMA query_only=ON")).unwrap();
        assert!(final_cut(&mut c,&s).is_err());assert!(c.is_autocommit());
    }
}
#[test] fn original_context_disagreement_refuses_before_capture() {
    let mut c=fixture::pre(burn(2),37);let s=observe_connection(&mut c,facts()).unwrap();
    assert!(s.matches(&facts()));
    for field in 0..6 {
        let mut f=facts();match field {
            0=>f.intent.command=[99;16],1=>f.terminal.binding_digest=[99;32],
            2=>f.ownership.owner=[99;16],3=>f.ownership.claim_version=3,
            4=>f.authority=[99;16],_=>f.terminal.stdout=b"forged",
        }
        assert!(!s.matches(&f));
    }
}
#[test] fn original_authority_lineage_and_context_refuse_at_observation() {
    for field in 0..4 {
        let mut positive=fixture::pre(burn(2),37);
        assert!(observe_connection(&mut positive,facts()).is_ok());
        let mut c=fixture::pre(burn(2),37);let mut f=facts();match field {
            0=>f.authority=[99;16],1=>f.lineage=runne_domain::id::EventLogLineageId::from_bytes([0;16]),
            2=>f.ownership.area=[99;100],_=>f.terminal.task=[99;16],
        }
        assert!(observe_connection(&mut c,f).is_err());
    }
}

#[test] fn final_capture_rejects_forged_intent_terminal_or_ownership() {
    for field in 0..3 {
        let mut positive=fixture::pre(burn(2),37);
        let seal=observe_connection(&mut positive,facts()).unwrap();fixture::finish(&positive);
        assert!(final_cut(&mut positive,&seal).is_ok());
        let mut c=fixture::pre(burn(2),37);let seal=observe_connection(&mut c,facts()).unwrap();
        fixture::finish(&c);let mut f=facts();
        let mut owned=f.ownership.expected(seal.burn,seal.burned_at);
        match field {0=>f.intent.command=[99;16],1=>f.terminal.fence=3,
            _=>owned.owner=[99;16]}
        assert!(capture_core::capture(&mut c,Limits::fixture(),Some(&f.intent),
            Some(&f.terminal),Some(&owned),Some(&seal)).is_err());
    }
}
#[test] fn query_only_and_nested_transaction_refuse() {
    let mut positive=fixture::pre(burn(2),37);
    assert!(observe_connection(&mut positive,facts()).is_ok());
    let mut c=fixture::pre(burn(2),37);c.execute_batch("PRAGMA query_only=OFF").unwrap();
    assert!(observe_connection(&mut c,facts()).is_err());
    let mut c=fixture::pre(burn(2),37);c.execute_batch("BEGIN").unwrap();
    assert!(observe_connection(&mut c,facts()).is_err());
}

#[test] fn further_burn_types_and_original_aliases_refuse() {
    for sql in ["UPDATE x2_permission_spent SET burned_at='37'",
        "UPDATE x2_permission_spent SET burned_at=-1",
        "UPDATE x2_permission_spent SET burn_id=X'01010101010101010101010101010101'",
        "UPDATE x2_permission_spent SET binding_digest=zeroblob(32)",
        "UPDATE x2_permission_spent SET area_identity=zeroblob(100)",
        "UPDATE x2_permission_spent SET owner_id=zeroblob(16)",
        "UPDATE x2_permission_spent SET owner_generation=zeroblob(8)",
        "UPDATE _daemon_info SET key=CAST(key AS BLOB)",
        "UPDATE _authority SET id=1.0",
        "UPDATE taskrun_local_command_attempts SET managed_area_identity=zeroblob(100)",
        "INSERT INTO taskrun_local_command_attempts SELECT * FROM taskrun_local_command_attempts"] {
        let mut positive=fixture::pre(burn(2),37);
        assert!(observe_connection(&mut positive,facts()).is_ok());
        let mut c=fixture::pre(burn(2),37);
        c.execute_batch(&format!("PRAGMA query_only=OFF;{sql};PRAGMA query_only=ON")).unwrap();
        assert!(observe_connection(&mut c,facts()).is_err());
    }
}
