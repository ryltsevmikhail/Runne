use runne_domain::verification::digest::*;
use uuid::Uuid;

#[test]
fn digest_from_valid_hex_roundtrip() {
    let hex = "a".repeat(64);
    let d = VerificationDigest::from_hex(&hex).unwrap();
    assert_eq!(d.to_hex(), hex);
    assert_eq!(d.as_bytes().len(), 32);
}

#[test]
fn digest_invalid_hex_rejected() {
    assert!(VerificationDigest::from_hex("gg".repeat(32).as_str()).is_err());
    assert!(VerificationDigest::from_hex("abc").is_err());
    assert!(VerificationDigest::from_hex("A".repeat(64).as_str()).is_err());
}

#[test]
fn evidence_set_digest_deterministic_and_order_independent() {
    let contract = DigestContract::new("runne:evidence-set:v1");
    let id1 = Uuid::now_v7();
    let id2 = Uuid::now_v7();
    let d1 = VerificationDigest::from_bytes([1u8; 32]);
    let d2 = VerificationDigest::from_bytes([2u8; 32]);

    let refs_a = vec![(id1, d1.clone()), (id2, d2.clone())];
    let refs_b = vec![(id2, d2.clone()), (id1, d1.clone())];
    assert_eq!(
        contract.compute_evidence_set(&refs_a).unwrap(),
        contract.compute_evidence_set(&refs_b).unwrap(),
        "different input order must produce same digest"
    );
}

#[test]
fn evidence_set_rejects_duplicates() {
    let contract = DigestContract::new("runne:evidence-set:v1");
    let id = Uuid::now_v7();
    let d = VerificationDigest::from_bytes([1u8; 32]);
    let refs = vec![(id, d.clone()), (id, d)];
    assert!(contract.compute_evidence_set(&refs).is_err());
}

#[test]
fn empty_evidence_set_valid() {
    let contract = DigestContract::new("runne:evidence-set:v1");
    let refs: Vec<(Uuid, VerificationDigest)> = vec![];
    let result = contract.compute_evidence_set(&refs).unwrap();
    assert!(!result.as_bytes().iter().all(|b| *b == 0));
}

#[test]
fn domain_tag_separation() {
    let c1 = DigestContract::new("runne:foo:v1");
    let c2 = DigestContract::new("runne:bar:v1");
    let d = VerificationDigest::from_bytes([1u8; 32]);
    assert_ne!(c1.compute(&[d.as_bytes()]), c2.compute(&[d.as_bytes()]));
}
