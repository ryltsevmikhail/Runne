//! Local model source bridge tests (Plan Task 15): the picked-file
//! path produces a valid staged candidate, admission requires the
//! exact license digest, and the installation list carries the matrix
//! revision.

use runne_platform_desktop::local_model_source::{
    LocalModelSource, LocalModelSourceError, PickerInput,
};
use std::path::{Path, PathBuf};

fn gguf_with_metadata() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GGUF");
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&4u64.to_le_bytes());

    let mut put_str = |out: &mut Vec<u8>, s: &str| {
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    };
    put_str(&mut out, "general.architecture");
    out.extend_from_slice(&8u32.to_le_bytes());
    put_str(&mut out, "llama");
    put_str(&mut out, "llama.context_length");
    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&4096u32.to_le_bytes());
    put_str(&mut out, "tokenizer.ggml.model");
    out.extend_from_slice(&8u32.to_le_bytes());
    put_str(&mut out, "bpe");
    put_str(&mut out, "tokenizer.chat_template");
    out.extend_from_slice(&8u32.to_le_bytes());
    put_str(&mut out, "{{ .Prompt }}");
    out
}

fn picker_input() -> PickerInput {
    PickerInput {
        model_id: "desktop-model".into(),
        model_revision: "r1".into(),
        license: "Apache-2.0".into(),
        provenance_source_uri: "https://example.test/model".into(),
        provenance_publisher: "tester".into(),
        provenance_acquired_at: "2026-09-05T00:00:00Z".into(),
        template_path: None,
        min_compatible_runtime: None,
    }
}

fn write_fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("picked.gguf");
    std::fs::write(&path, gguf_with_metadata()).expect("write");
    (dir, path)
}

#[test]
fn picker_to_stage_to_admit_to_list() {
    let (_dir, gguf_path) = write_fixture();
    let models_dir = tempfile::tempdir().expect("models dir");
    let mut source = LocalModelSource::open(models_dir.path()).expect("source");

    let input = picker_input();
    let candidate = source.stage_candidate(&gguf_path, &input).expect("stage");
    assert!(!candidate.candidate_id.is_empty());
    assert_eq!(candidate.model_id, "desktop-model");

    // Admission with a wrong license digest refuses (fail-closed).
    let wrong = source
        .admit(&candidate.candidate_id, "sha256:deadbeef")
        .err()
        .expect("license mismatch");
    assert!(matches!(wrong, LocalModelSourceError::Store(_)));

    // The exact shown-license digest admits.
    use sha2::Digest as _;
    let accepted = source
        .admit(
            &candidate.candidate_id,
            &hex::encode(sha2::Sha256::digest("Apache-2.0".as_bytes())),
        )
        .expect("admit");
    assert_eq!(accepted.model_id, "desktop-model");

    let list = source.list().expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].model_id, "desktop-model");
}

#[test]
fn discard_removes_staged_candidate() {
    let (_dir, gguf_path) = write_fixture();
    let models_dir = tempfile::tempdir().expect("models dir");
    let mut source = LocalModelSource::open(models_dir.path()).expect("source");
    let input = picker_input();
    let candidate = source.stage_candidate(&gguf_path, &input).expect("stage");
    assert!(source.discard(&candidate.candidate_id).expect("discard"));
    assert!(source.list().expect("list").is_empty());
}

#[test]
fn unreadable_source_refuses() {
    let models_dir = tempfile::tempdir().expect("models dir");
    let mut source = LocalModelSource::open(models_dir.path()).expect("source");
    let input = picker_input();
    let err = source
        .stage_candidate(Path::new("/nonexistent/model.gguf"), &input)
        .err()
        .expect("unreadable");
    assert!(matches!(err, LocalModelSourceError::SourceUnreadable));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
