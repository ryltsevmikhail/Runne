use runne_project_owner_authority::{
    AuthorityError, PurposeProfileV1, UnsignedReceipt, canonical_checked_in_receipt,
    verify_receipt_bytes,
};
use sha2::{Digest, Sha256};

mod receipt_support;

fn canonical_bytes() -> Vec<u8> {
    let (receipt, _, _) = receipt_support::signed();
    canonical_checked_in_receipt(&receipt.unsigned, &receipt.signature).expect("canonical")
}

#[test]
fn raw_verification_accepts_only_exact_canonical_checked_in_bytes() {
    let (_, trust, anchor) = receipt_support::signed();
    let bytes = canonical_bytes();
    verify_receipt_bytes(
        &bytes,
        Sha256::digest(&bytes).into(),
        &PurposeProfileV1::v1_platform_scope(),
        &trust,
        &anchor,
    )
    .expect("canonical raw receipt");

    for changed in [
        bytes[..bytes.len() - 1].to_vec(),
        String::from_utf8(bytes.clone())
            .expect("utf8")
            .replace('\n', "\r\n")
            .into_bytes(),
        String::from_utf8(bytes.clone())
            .expect("utf8")
            .replace("{\"documents\"", "{ \"documents\"")
            .into_bytes(),
        reorder_root(&String::from_utf8(bytes.clone()).expect("utf8")).into_bytes(),
    ] {
        assert_eq!(
            verify_receipt_bytes(
                &changed,
                Sha256::digest(&changed).into(),
                &PurposeProfileV1::v1_platform_scope(),
                &trust,
                &anchor,
            ),
            Err(AuthorityError::InvalidCanonicalReceipt)
        );
    }
}

fn reorder_root(value: &str) -> String {
    value
        .replacen(
            "{\"documents\"",
            "{\"issued_at\":\"2026-08-12T00:00:00Z\",\"documents\"",
            1,
        )
        .replacen(",\"issued_at\":\"2026-08-12T00:00:00Z\"", "", 1)
}

#[test]
fn raw_verification_rejects_duplicate_unknown_and_noncanonical_signature() {
    let (_, trust, anchor) = receipt_support::signed();
    let text = String::from_utf8(canonical_bytes()).expect("utf8");
    for changed in [
        text.replacen('{', "{\"role\":\"PROJECT_OWNER\",", 1),
        text.replace("\"signature\":\"", "\"unexpected\":true,\"signature\":\""),
        text.replace("\"signature\":\"", "\"signature\":\"A"),
        text.replacen("\"}\n", "=\"}\n", 1),
    ] {
        assert!(
            verify_receipt_bytes(
                changed.as_bytes(),
                Sha256::digest(text.as_bytes()).into(),
                &PurposeProfileV1::v1_platform_scope(),
                &trust,
                &anchor,
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_impossible_utc_calendar_and_private_error_context() {
    let (_, trust, anchor) = receipt_support::signed();
    let bytes = canonical_bytes();
    for date in [
        "2026-02-29T00:00:00Z",
        "2024-04-31T00:00:00Z",
        "2024-01-01T24:00:00Z",
        "0000-01-01T00:00:00Z",
    ] {
        let changed = String::from_utf8(bytes.clone())
            .expect("utf8")
            .replace("2026-08-12T00:00:00Z", date);
        assert_eq!(
            verify_receipt_bytes(
                changed.as_bytes(),
                Sha256::digest(changed.as_bytes()).into(),
                &PurposeProfileV1::v1_platform_scope(),
                &trust,
                &anchor,
            ),
            Err(AuthorityError::InvalidReceiptTrust)
        );
    }
    let private = "private\\u001bowner@example.test";
    for error in [
        UnsignedReceipt::from_json(format!(r#"{{"{private}":true}}"#).as_bytes())
            .expect_err("unknown key"),
        UnsignedReceipt::from_json(format!(r#"{{"{private}":true,"{private}":false}}"#).as_bytes())
            .expect_err("duplicate key"),
        duplicate_path_error(private),
    ] {
        assert!(!error.to_string().contains("private"));
        assert!(!error.to_string().contains("owner@example.test"));
    }
}

#[test]
fn raw_verification_rejects_an_unexpected_external_receipt_digest() {
    let (_, trust, anchor) = receipt_support::signed();
    let bytes = canonical_bytes();
    let mut wrong = <[u8; 32]>::from(Sha256::digest(&bytes));
    wrong[0] ^= 1;
    assert_eq!(
        verify_receipt_bytes(
            &bytes,
            wrong,
            &PurposeProfileV1::v1_platform_scope(),
            &trust,
            &anchor,
        ),
        Err(AuthorityError::InvalidReceiptDigest)
    );
}

fn duplicate_path_error(private: &str) -> AuthorityError {
    let (receipt, _, _) = receipt_support::signed();
    let mut value = serde_json::to_value(receipt.unsigned).expect("receipt JSON");
    let documents = value["documents"].as_array_mut().expect("documents");
    documents[1]["path"] = serde_json::Value::String(private.into());
    documents[0]["path"] = serde_json::Value::String(private.into());
    UnsignedReceipt::from_json(&serde_json::to_vec(&value).expect("JSON"))
        .expect_err("duplicate path")
}
