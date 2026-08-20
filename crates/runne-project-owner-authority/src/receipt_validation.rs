//! Receipt profile, Git-object, and trust-binding validation.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AuthorityError, GitSubject, ProjectOwnerTrustConfigV1, UnsignedReceipt, key_id,
    receipt::{DocumentBinding, PROFILE, PurposeProfileV1, RECEIPT_SCHEMA, REPOSITORY, ROLE},
};

pub fn validate_schema_digests(trust: &ProjectOwnerTrustConfigV1) -> Result<(), AuthorityError> {
    if trust.schema_digests != crate::v1_platform_scope_schema_digests() {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    Ok(())
}

pub fn validate_documents(
    profile: &PurposeProfileV1,
    documents: &[DocumentBinding],
) -> Result<(), AuthorityError> {
    let expected = PurposeProfileV1::v1_platform_scope();
    if profile != &expected || profile.required_paths.iter().any(|path| wildcard(path)) {
        return Err(AuthorityError::InvalidPurposeProfile);
    }
    let mut paths = BTreeSet::new();
    let mut schemas = BTreeMap::new();
    for document in documents {
        validate_document_binding(document)?;
        if !paths.insert(document.path.clone()) {
            return Err(AuthorityError::InvalidPurposeProfile);
        }
        schemas.insert(document.path.clone(), document.schema_id.clone());
    }
    if paths != profile.required_paths
        || schemas.len() != profile.required_paths.len()
        || schemas
            .into_iter()
            .any(|(path, schema)| profile.required_schema_ids.get(&path) != schema.as_ref())
    {
        return Err(AuthorityError::InvalidPurposeProfile);
    }
    Ok(())
}

pub fn validate_subject_bindings(
    profile: &PurposeProfileV1,
    documents: &[DocumentBinding],
    subject: &GitSubject,
) -> Result<(), AuthorityError> {
    let width = subject_oid_width(subject)?;
    validate_documents(profile, documents)?;
    if documents
        .iter()
        .any(|document| !lower_hex(&document.blob_oid, width))
    {
        return Err(AuthorityError::InvalidDocumentBinding);
    }
    Ok(())
}

pub fn validate_receipt_trust(
    receipt: &UnsignedReceipt,
    trust: &ProjectOwnerTrustConfigV1,
    profile: &PurposeProfileV1,
) -> Result<(), AuthorityError> {
    if receipt.schema_version != RECEIPT_SCHEMA
        || receipt.repository_id != REPOSITORY
        || receipt.role != ROLE
        || receipt.purpose != profile.purpose
        || receipt.profile != PROFILE
        || receipt.key_id != hex(&key_id(&trust.public_key))
        || receipt.key_epoch != trust.epoch
        || receipt.trust_config_sha256 != hex(&trust.sha256()?)
        || !valid_timestamp(&receipt.issued_at)
    {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    Ok(())
}

pub fn validate_document_binding(document: &DocumentBinding) -> Result<(), AuthorityError> {
    if !safe_path(&document.path)
        || document.mode != "100644"
        || !lower_hex(&document.blob_oid, 40) && !lower_hex(&document.blob_oid, 64)
        || !lower_hex(&document.content_sha256, 64)
        || document
            .schema_id
            .as_deref()
            .is_some_and(|id| !schema_id(id))
    {
        return Err(AuthorityError::InvalidDocumentBinding);
    }
    Ok(())
}

pub fn subject_oid_width(subject: &GitSubject) -> Result<usize, AuthorityError> {
    let width = match subject.object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        _ => return Err(AuthorityError::InvalidDocumentBinding),
    };
    if !lower_hex(&subject.commit_oid, width) || !lower_hex(&subject.tree_oid, width) {
        return Err(AuthorityError::InvalidDocumentBinding);
    }
    Ok(width)
}

fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', '\0', '*', '?', '[', ']'])
        && path.chars().all(|character| !character.is_control())
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.trim() == part)
}

fn wildcard(path: &str) -> bool {
    path.contains(['*', '?', '[', ']'])
}

fn schema_id(value: &str) -> bool {
    let Some((name, version)) = value
        .strip_prefix("gocode.")
        .and_then(|item| item.split_once('/'))
    else {
        return false;
    };
    !name.is_empty()
        && !version.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

pub fn valid_timestamp(value: &str) -> bool {
    if value.len() != 20
        || ![4, 7, 10, 13, 16, 19].into_iter().all(|index| {
            value.as_bytes()[index]
                == match index {
                    4 | 7 => b'-',
                    10 => b'T',
                    13 | 16 => b':',
                    _ => b'Z',
                }
        })
        || !value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0..4),
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    ) else {
        return false;
    };
    year >= 1
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour < 24
        && minute < 60
        && second < 60
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

pub fn lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]])
        .map(char::from)
        .collect()
}
