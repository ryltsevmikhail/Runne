use super::{
    AuthorityReviewV1, ReviewBackup, ReviewDocument, ReviewError, ReviewOutput, ReviewRotation,
    ReviewSubject, SCHEMA,
};

pub(super) fn validate(x: &AuthorityReviewV1) -> Result<(), ReviewError> {
    let fixed = x.schema_version == SCHEMA
        && x.repository_id == "runne"
        && x.key_epoch > 0
        && matches!(
            x.operation.as_str(),
            "init" | "sign" | "rotate" | "backup" | "restore" | "trust-reset"
        )
        && matches!(
            x.continuity.as_str(),
            "genesis" | "continuous" | "restore-same-anchor" | "discontinuity"
        );
    let hashes = [&x.trust_config_sha256, &x.key_id, &x.key_fingerprint]
        .into_iter()
        .all(|v| lower_hex(v, 64))
        && x.signing_transcript_sha256
            .as_deref()
            .is_none_or(|v| lower_hex(v, 64));
    let nested = x.documents.iter().all(valid_document)
        && x.documents
            .iter()
            .enumerate()
            .all(|(i, doc)| x.documents[..i].iter().all(|prior| prior.path != doc.path))
        && x.subject.as_ref().is_none_or(valid_subject)
        && x.output.as_ref().is_none_or(valid_output)
        && x.rotation.as_ref().is_none_or(valid_rotation)
        && x.backup.as_ref().is_none_or(valid_backup);
    if !(fixed
        && hashes
        && optional_public(x.purpose.as_deref())
        && optional_public(x.profile.as_deref())
        && x.issued_at.as_deref().is_none_or(valid_timestamp)
        && nested)
    {
        return Err(ReviewError);
    }
    if let Some(subject) = &x.subject {
        let width = oid_width(&subject.object_format).ok_or(ReviewError)?;
        if x.documents
            .iter()
            .any(|doc| !lower_hex(&doc.blob_oid, width))
        {
            return Err(ReviewError);
        }
    }
    Ok(())
}
fn valid_document(x: &ReviewDocument) -> bool {
    x.mode == "100644"
        && safe_path(&x.path)
        && (lower_hex(&x.blob_oid, 40) || lower_hex(&x.blob_oid, 64))
        && lower_hex(&x.content_sha256, 64)
        && x.schema_id.as_deref().is_none_or(schema_id)
}
fn valid_subject(x: &ReviewSubject) -> bool {
    oid_width(&x.object_format)
        .is_some_and(|w| lower_hex(&x.commit_oid, w) && lower_hex(&x.tree_oid, w))
}
fn valid_output(x: &ReviewOutput) -> bool {
    match x.kind.as_str() {
        "repository-artifact-set-v1" => {
            x.artifact_sha256
                .as_deref()
                .is_some_and(|v| lower_hex(v, 64))
                && x.byte_length.is_some_and(|n| n > 0)
                && x.locator == "rotation+successor-trust"
        }
        _ => {
            x.artifact_sha256
                .as_deref()
                .is_none_or(|v| lower_hex(v, 64))
                && match x.kind.as_str() {
                    "repository-relative" => safe_path(&x.locator),
                    "external-path-sha256" => lower_hex(&x.locator, 64),
                    _ => false,
                }
        }
    }
}
fn valid_rotation(x: &ReviewRotation) -> bool {
    x.old_epoch > 0
        && x.new_epoch > x.old_epoch
        && lower_hex(&x.new_key_fingerprint, 64)
        && lower_hex(&x.new_key_id, 64)
        && lower_hex(&x.old_authorization_payload_sha256, 64)
        && lower_hex(&x.old_key_id, 64)
        && lower_hex(&x.predecessor_config_sha256, 64)
        && x.new_public_key.len() == 43
        && x.new_public_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn valid_backup(x: &ReviewBackup) -> bool {
    x.kdf_algorithm == "argon2id"
        && x.iterations > 0
        && x.memory_kib > 0
        && x.parallelism > 0
        && lower_hex(&x.backup_bytes_sha256, 64)
}
fn optional_public(x: Option<&str>) -> bool {
    x.is_none_or(public_text)
}
fn public_text(x: &str) -> bool {
    !x.is_empty() && x.trim() == x && !x.bytes().any(|b| b.is_ascii_control())
}
fn oid_width(x: &str) -> Option<usize> {
    match x {
        "sha1" => Some(40),
        "sha256" => Some(64),
        _ => None,
    }
}
fn lower_hex(x: &str, width: usize) -> bool {
    x.len() == width
        && x.bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b.is_ascii_hexdigit()))
}
fn safe_path(x: &str) -> bool {
    !x.is_empty()
        && !x.starts_with('/')
        && !x.contains(['\\', '\0'])
        && x.bytes().all(|b| !b.is_ascii_control())
        && x.split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".." && p.trim() == p)
}
fn schema_id(x: &str) -> bool {
    x.strip_prefix("runne.")
        .and_then(|x| x.split_once('/'))
        .is_some_and(|(name, ver)| {
            !name.is_empty()
                && !ver.is_empty()
                && name.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-')
                })
                && ver.bytes().all(|b| b.is_ascii_digit())
        })
}
fn valid_timestamp(x: &str) -> bool {
    let shape = x.len() == 20
        && [4, 7, 10, 13, 16, 19].into_iter().all(|i| {
            x.as_bytes()[i]
                == match i {
                    4 | 7 => b'-',
                    10 => b'T',
                    13 | 16 => b':',
                    _ => b'Z',
                }
        })
        && x.bytes()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit());
    if !shape {
        return false;
    }
    let n = |r: std::ops::Range<usize>| x[r].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (n(0..4), n(5..7), n(8..10), n(11..13), n(14..16), n(17..19))
    else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}
