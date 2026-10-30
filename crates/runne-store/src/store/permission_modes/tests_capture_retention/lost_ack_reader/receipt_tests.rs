//! Authored before receipt.rs; source-only, no observed RED/GREEN.
use super::*;
fn intent() -> Intent<'static> {
    Intent { command: [7;16], task: [9;16], authority: "ra", principal: "p",
        key: b"k", fingerprint: [3;32], version: 5 }
}
// Literal independent vector, not built with the validator or production codec.
fn scope() -> Vec<u8> {
    let mut bytes = vec![0,1,0,2,b'r',b'a',0,1,b'p',5,1];
    bytes.extend_from_slice(&[9;16]); bytes
}
fn outcome() -> Vec<u8> {
    let mut bytes = vec![0,1,5]; bytes.extend_from_slice(&[9;16]);
    bytes.extend_from_slice(&[0,0,0,0,0,0,0,5]); bytes
}
fn check(scope: &[u8], outcome: &[u8]) -> bool {
    validate(&intent(), &Receipt { command: &[7;16], scope, key: b"k",
        fingerprint: &[3;32], outcome, committed_at: 11 }).is_ok()
}
#[test] fn canonical_original_receipt() { assert!(check(&scope(), &outcome())); }
#[test] fn every_scope_byte_matters() {
    let good=scope(); assert!(check(&good,&outcome()));
    for n in 0..good.len() { let mut bad=good.clone(); bad[n]^=1;
        assert!(!check(&bad,&outcome()),"scope byte {n}"); }
}
#[test] fn every_outcome_byte_matters() {
    let good=outcome(); assert!(check(&scope(),&good));
    for n in 0..good.len() { let mut bad=good.clone(); bad[n]^=1;
        assert!(!check(&scope(),&bad),"outcome byte {n}"); }
}
#[test] fn all_scope_prefixes_refuse() {
    let good=scope(); assert!(check(&good,&outcome()));
    for n in 0..good.len() { assert!(!check(&good[..n],&outcome())); }
}
#[test] fn all_outcome_prefixes_refuse() {
    let good=outcome(); assert!(check(&scope(),&good));
    for n in 0..good.len() { assert!(!check(&scope(),&good[..n])); }
}
#[test] fn trailing_scope_bytes_refuse() {
    let mut bad=scope(); assert!(check(&bad,&outcome())); bad.push(0);
    assert!(!check(&bad,&outcome()));
}
#[test] fn trailing_outcome_bytes_refuse() {
    let mut bad=outcome(); assert!(check(&scope(),&bad)); bad.push(0);
    assert!(!check(&scope(),&bad));
}
#[test] fn receipt_identity_key_fingerprint_and_time() {
    let s=scope();let o=outcome();let i=intent();
    let mut r=Receipt { command:&[7;16],scope:&s,key:b"k",
        fingerprint:&[3;32],outcome:&o,committed_at:11 };
    assert!(validate(&i,&r).is_ok());
    r.command=&[8;16];assert!(validate(&i,&r).is_err());r.command=&[7;16];
    r.key=b"x";assert!(validate(&i,&r).is_err());r.key=b"k";
    r.fingerprint=&[4;32];assert!(validate(&i,&r).is_err());r.fingerprint=&[3;32];
    r.committed_at=0;assert!(validate(&i,&r).is_err());
    r.committed_at=-1;assert!(validate(&i,&r).is_err());
}
#[test] fn invalid_intent_refuses_before_acceptance() {
    let s=scope();let o=outcome();let mut i=intent();
    let r=Receipt { command:&[7;16],scope:&s,key:b"k",
        fingerprint:&[3;32],outcome:&o,committed_at:11 };
    assert!(validate(&i,&r).is_ok());
    i.version=0;assert!(validate(&i,&r).is_err());i.version=5;
    i.key=b"";assert!(validate(&i,&r).is_err());i.key=b"k";
    i.authority="";assert!(validate(&i,&r).is_err());i.authority="ra";
    i.principal="";assert!(validate(&i,&r).is_err());
}
#[test] fn bounded_intent_fields() {
    let long="a".repeat(65536);let key=vec![0;257];
    let s=scope();let o=outcome();let mut i=intent();
    let r=Receipt { command:&[7;16],scope:&s,key:b"k",
        fingerprint:&[3;32],outcome:&o,committed_at:11 };
    assert!(validate(&i,&r).is_ok());i.authority=&long;
    assert!(validate(&i,&r).is_err());i.authority="ra";i.principal=&long;
    assert!(validate(&i,&r).is_err());i.principal="p";i.key=&key;
    assert!(validate(&i,&r).is_err());i.key=b"k";i.version=i64::MAX as u64+1;
    assert!(validate(&i,&r).is_err());
}
