//! Builder refusals (Plan Task 17 Step 2): missing authority fields,
//! unknown/corrupt GGUF, missing template and a runtime-floor
//! violation are all refused — the builder never invents fields.

mod builder_common;

use builder_common::{gguf_with_metadata, gguf_without_metadata};
use runne_local_model::builder_error::BuilderError;
use runne_local_model::{BUILDER_CONTRACT_VERSION, UserSupplied, build_candidate_manifest};
use std::io::Cursor;

fn build(
    bytes: &[u8],
    mutate: impl FnOnce(&mut UserSupplied),
) -> Result<runne_local_model::CandidateManifest, BuilderError> {
    let mut u = builder_common::full_user();
    mutate(&mut u);
    let mut r = Cursor::new(bytes.to_vec());
    build_candidate_manifest(&mut r, &u, BUILDER_CONTRACT_VERSION)
}

#[test]
fn missing_license_refuses() {
    let err = build(&gguf_with_metadata(), |u| u.license = None).expect_err("license");
    assert_eq!(err, BuilderError::LicenseMissing);
}

#[test]
fn missing_provenance_fields_refuse() {
    for m in [
        |u: &mut UserSupplied| u.provenance_source_uri = None,
        |u: &mut UserSupplied| u.provenance_publisher = None,
        |u: &mut UserSupplied| u.provenance_acquired_at = None,
    ] {
        let err = build(&gguf_with_metadata(), m).expect_err("provenance");
        assert_eq!(err, BuilderError::LicenseMissing);
    }
}

#[test]
fn unknown_gguf_refuses() {
    // Long enough to pass the header-length gate; magic is wrong.
    let err = build(b"NOTGGUF____________________________", |_| {}).expect_err("magic");
    assert_eq!(err, BuilderError::UnsupportedFormat);
}

#[test]
fn missing_metadata_evidence_refuses() {
    // No tokenizer family / no context length / no architecture.
    let err = build(&gguf_without_metadata(), |_| {}).expect_err("metadata");
    assert_eq!(err, BuilderError::ArtifactUnparseable);
}

#[test]
fn missing_template_everywhere_refuses() {
    let err = build(&builder_common::gguf_without_template(), |_| {}).expect_err("template");
    assert_eq!(err, BuilderError::TemplateMissing);
}

#[test]
fn embedded_template_and_user_file_conflict_refuses() {
    let err = build(&gguf_with_metadata(), |u| {
        u.chat_template = Some(b"user template".to_vec());
    })
    .expect_err("conflict");
    assert_eq!(err, BuilderError::DeterminismViolation);
}

#[test]
fn lowering_runtime_below_builder_floor_refuses() {
    let err = build(&gguf_with_metadata(), |u| {
        u.min_compatible_runtime = Some("0.0.9".into());
    })
    .expect_err("floor");
    assert_eq!(err, BuilderError::DeterminismViolation);
}

#[test]
fn raising_runtime_is_allowed() {
    let built = build(&gguf_with_metadata(), |u| {
        u.min_compatible_runtime = Some("9.0.0".into());
    })
    .expect("raise allowed");
    let text = String::from_utf8(built.canonical_bytes).expect("utf8");
    assert!(text.contains("\"minCompatibleRuntime\":\"9.0.0\""));
}
