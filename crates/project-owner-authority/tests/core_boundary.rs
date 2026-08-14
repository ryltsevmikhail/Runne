use gocode_project_owner_authority::{
    AuthorityError, DocumentBinding, GitSubject, KeyRotationV1, ProjectOwnerTrustConfigV1,
    PurposeProfileV1, canonical_checked_in_receipt, genesis_pop_transcript, inspect_receipt_bytes,
    rotation_new_pop_transcript, rotation_old_authorization_transcript,
    verify_receipt_bytes_against_subject,
};
use sha2::{Digest, Sha256};

mod receipt_support;
#[allow(dead_code)]
mod rotation_support;

#[test]
fn public_pop_transcripts_are_exact_protocol_transcripts() {
    let (_, trust, _) = receipt_support::signed();
    let genesis = genesis_pop_transcript(&trust).expect("genesis transcript");
    assert_eq!(&genesis[4..38], b"gocode.project-owner.genesis-pop/1");

    let rotation = rotation_support::rotation(&trust);
    let new_pop = rotation_new_pop_transcript(&trust, &rotation).expect("new PoP transcript");
    assert_eq!(
        &new_pop[4..59],
        b"gocode.project-owner.rotation-new-proof-of-possession/1"
    );
    let old_authorization =
        rotation_old_authorization_transcript(&rotation).expect("old authorization transcript");
    assert_eq!(
        &old_authorization[4..53],
        b"gocode.project-owner.rotation-old-authorization/1"
    );
}

#[test]
fn trust_config_accepts_only_exact_canonical_json() {
    let (_, trust, _) = receipt_support::signed();
    let canonical = trust.to_canonical_json().expect("canonical trust");
    assert_eq!(ProjectOwnerTrustConfigV1::from_json(&canonical), Ok(trust));
    for changed in [
        canonical[..canonical.len() - 1].to_vec(),
        String::from_utf8(canonical.clone())
            .expect("utf8")
            .replace("{\"epoch\"", "{ \"epoch\"")
            .into_bytes(),
        String::from_utf8(canonical.clone())
            .expect("utf8")
            .replacen('{', "{\"epoch\":1,", 1)
            .into_bytes(),
        String::from_utf8(canonical)
            .expect("utf8")
            .replace(
                "\"schema_version\"",
                "\"unexpected\":true,\"schema_version\"",
            )
            .into_bytes(),
    ] {
        assert!(ProjectOwnerTrustConfigV1::from_json(&changed).is_err());
    }
}

#[test]
fn rotation_accepts_only_exact_canonical_json() {
    let (_, trust, _) = receipt_support::signed();
    let rotation = rotation_support::rotation(&trust);
    let canonical = rotation.to_canonical_json().expect("canonical rotation");
    assert_eq!(KeyRotationV1::from_json(&canonical), Ok(rotation));
    for changed in [
        canonical[..canonical.len() - 1].to_vec(),
        String::from_utf8(canonical.clone())
            .expect("utf8")
            .replace("{\"new_epoch\"", "{ \"new_epoch\"")
            .into_bytes(),
        String::from_utf8(canonical.clone())
            .expect("utf8")
            .replacen('{', "{\"new_epoch\":2,", 1)
            .into_bytes(),
        String::from_utf8(canonical)
            .expect("utf8")
            .replace(
                "\"schema_version\"",
                "\"unexpected\":true,\"schema_version\"",
            )
            .into_bytes(),
    ] {
        assert!(KeyRotationV1::from_json(&changed).is_err());
    }
}

#[test]
fn raw_receipt_verification_binds_exact_subject_and_documents() {
    let (receipt, trust, anchor) = receipt_support::signed();
    let bytes = canonical_checked_in_receipt(&receipt.unsigned, &receipt.signature)
        .expect("canonical receipt");
    let expected_subject = receipt.unsigned.subject.clone();
    let expected_documents = bindings(&receipt);
    verify_receipt_bytes_against_subject(
        &bytes,
        Sha256::digest(&bytes).into(),
        &PurposeProfileV1::v1_platform_scope(),
        &trust,
        &anchor,
        &expected_subject,
        &expected_documents,
    )
    .expect("exact receipt binding");

    let changed_subject = GitSubject {
        commit_oid: "a".repeat(40),
        ..expected_subject
    };
    assert_eq!(
        verify_receipt_bytes_against_subject(
            &bytes,
            Sha256::digest(&bytes).into(),
            &PurposeProfileV1::v1_platform_scope(),
            &trust,
            &anchor,
            &changed_subject,
            &expected_documents,
        ),
        Err(AuthorityError::InvalidReceiptTrust)
    );
    let mut changed_documents = expected_documents;
    changed_documents[0].blob_oid = "a".repeat(40);
    assert_eq!(
        verify_receipt_bytes_against_subject(
            &bytes,
            Sha256::digest(&bytes).into(),
            &PurposeProfileV1::v1_platform_scope(),
            &trust,
            &anchor,
            &receipt.unsigned.subject,
            &changed_documents,
        ),
        Err(AuthorityError::InvalidDocumentBinding)
    );
}

#[test]
fn inspection_returns_only_canonical_untrusted_receipt_bindings() {
    let (receipt, _, _) = receipt_support::signed();
    let bytes = canonical_checked_in_receipt(&receipt.unsigned, &[0; 64])
        .expect("canonical but unauthenticated receipt");
    let inspected = inspect_receipt_bytes(&bytes).expect("strict canonical inspection");
    assert_eq!(inspected.subject(), &receipt.unsigned.subject);
    assert_eq!(inspected.documents(), bindings(&receipt));
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(inspected.checked_in_sha256(), digest);

    let text = String::from_utf8(bytes).expect("utf8");
    for changed in [
        text.replace('\n', "\r\n").into_bytes(),
        text.replace("{\"documents\"", "{ \"documents\"")
            .into_bytes(),
        text.replacen('{', "{\"role\":\"PROJECT_OWNER\",", 1)
            .into_bytes(),
        text.replace("\"signature\":", "\"unexpected\":true,\"signature\":")
            .into_bytes(),
        text.trim_end_matches('\n').as_bytes().to_vec(),
        text.replace("\"signature\":\"", "\"signature\":\"A")
            .into_bytes(),
    ] {
        assert!(inspect_receipt_bytes(&changed).is_err());
    }
}

fn bindings(receipt: &gocode_project_owner_authority::SignedReceipt) -> Vec<DocumentBinding> {
    let mut bindings = receipt
        .unsigned
        .documents
        .iter()
        .map(|document| DocumentBinding {
            path: document.path.clone(),
            mode: document.mode.clone(),
            blob_oid: document.blob_oid.clone(),
            content_sha256: document.content_sha256.clone(),
            byte_length: document.byte_length,
            schema_id: document.schema_id.clone(),
        })
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    bindings
}
