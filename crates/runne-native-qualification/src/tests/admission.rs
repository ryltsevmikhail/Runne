use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::{admission_bundle, sign, sign_run_context, unsigned_run_context, unsigned_ticket};
use crate::{
    MAX_ADMISSION_BUNDLE_BYTES, PendingQualificationAdmission, QualificationAdmissionError,
};

fn valid_pair() -> (Vec<u8>, Vec<u8>) {
    let ticket = sign(&unsigned_ticket(), &SigningKey::from_bytes(&[7; 32]));
    let context = sign_run_context(
        &unsigned_run_context(Sha256::digest(&ticket).into()),
        &SigningKey::from_bytes(&[9; 32]),
    );
    (context, ticket)
}

#[test]
fn exact_context_and_unchanged_ticket_bundle_is_admitted() {
    let (context, ticket) = valid_pair();
    PendingQualificationAdmission::from_admitted_bundle(admission_bundle(&context, &ticket))
        .expect("valid bounded admission bundle");
}

#[test]
fn admission_rejects_crossed_ticket_digest_and_later_context_expiry() {
    let (context, ticket) = valid_pair();
    let other_ticket = sign(&unsigned_ticket(), &SigningKey::from_bytes(&[8; 32]));
    assert_eq!(
        PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
            &context,
            &other_ticket
        ))
        .err(),
        Some(QualificationAdmissionError)
    );

    let mut value = unsigned_run_context(Sha256::digest(&ticket).into());
    value["expires_at"] = json!(super::NOW + 601);
    let late_context = sign_run_context(&value, &SigningKey::from_bytes(&[9; 32]));
    assert_eq!(
        PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
            &late_context,
            &ticket
        ))
        .err(),
        Some(QualificationAdmissionError)
    );
}

#[test]
fn admission_rejects_raw_ticket_bad_header_lengths_and_exact_eof_failures() {
    let (context, ticket) = valid_pair();
    let valid = admission_bundle(&context, &ticket);
    let mut cases = vec![ticket, vec![], valid[..valid.len() - 1].to_vec()];
    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut bad_magic = valid.clone();
    bad_magic[0] ^= 1;
    cases.push(bad_magic);
    let mut bad_version = valid.clone();
    bad_version[8] = 2;
    cases.push(bad_version);
    for offset in [9_usize, 13] {
        let mut zero = valid.clone();
        zero[offset..offset + 4].copy_from_slice(&0_u32.to_be_bytes());
        cases.push(zero);
        let mut overflow = valid.clone();
        overflow[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        cases.push(overflow);
    }
    cases.push(vec![0; MAX_ADMISSION_BUNDLE_BYTES + 1]);
    for bytes in cases {
        assert_eq!(
            PendingQualificationAdmission::from_admitted_bundle(bytes).err(),
            Some(QualificationAdmissionError)
        );
    }
}

#[test]
fn admission_rejects_oversized_members_and_semantically_invalid_members() {
    let (context, ticket) = valid_pair();
    let oversized_context = vec![b'x'; 2_049];
    let oversized_ticket = vec![b'x'; 4_097];
    for bytes in [
        admission_bundle(&oversized_context, &ticket),
        admission_bundle(&context, &oversized_ticket),
    ] {
        assert_eq!(
            PendingQualificationAdmission::from_admitted_bundle(bytes).err(),
            Some(QualificationAdmissionError)
        );
    }
    let mut bad_context = context;
    bad_context[0] = b'[';
    assert_eq!(
        PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
            &bad_context,
            &ticket
        ))
        .err(),
        Some(QualificationAdmissionError)
    );
}
