//! CPU inference qualification (Plan Task 9 Step 2). Skipped unless the
//! documented fixture is present: set `RUNNE_LLAMA_TEST_GGUF` to the
//! path of a small licensed GGUF model (see
//! docs/golden/local-engine/fixtures/README.md). Never downloads a
//! model during a test.

#![cfg(feature = "backend-llama-cpp")]

use runne_inference_protocol::{WorkerBackendConfig, WorkerErrorCode, WorkerLoad};
use runne_llama_worker::engine::{EngineBackend, EngineItem, EngineOutcome};
use runne_llama_worker::llama_context::LlamaEngine;
use sha2::Digest as _;
use std::os::fd::OwnedFd;

fn fixture() -> Option<(OwnedFd, WorkerLoad)> {
    let path = std::env::var("RUNNE_LLAMA_TEST_GGUF").ok()?;
    let bytes = std::fs::read(&path).expect("read fixture");
    assert!(bytes.len() > 4, "fixture too small");
    assert_eq!(&bytes[..4], b"GGUF", "fixture must be a GGUF image");
    let digest = format!(
        "sha256:{}",
        sha2::Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let file = std::fs::File::open(&path).expect("open fixture");
    let load = WorkerLoad {
        model_identity: "test:fixture:gguf".into(),
        load_id: [9; 16],
        artifact_digest: digest,
        byte_length: bytes.len() as u64,
        load_fence: [9; 16],
    };
    Some((file.into(), load))
}

#[test]
fn llama_cpu_loads_and_generates_deterministically() {
    let Some((artifact, load)) = fixture() else {
        eprintln!(
            "skipped: RUNNE_LLAMA_TEST_GGUF not set; see \
             docs/golden/local-engine/fixtures/README.md"
        );
        return;
    };
    let config = WorkerBackendConfig {
        context_max_tokens: 512,
        output_max_tokens: 16,
        gpu_layers: 0,
        threads: 2,
        seed: 42,
    };
    let mut engine = LlamaEngine::new().expect("backend");
    engine
        .load(&load, &config, artifact)
        .expect("verified load");

    let (first, outcome) = engine
        .infer([1; 16], [2; 16], [3; 16], "Say hello.")
        .expect("first run");
    assert_eq!(outcome, EngineOutcome::Stopped);
    let text: String = first
        .iter()
        .filter_map(|i| match i {
            EngineItem::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    assert!(!text.is_empty(), "expected non-empty output");
    assert!(first.iter().any(
        |i| matches!(i, EngineItem::Usage { prompt_tokens, output_tokens }
            if *output_tokens > 0 && *output_tokens <= 16)
    ));
    assert!(first.iter().any(|i| matches!(i, EngineItem::Finish)));

    // Deterministic seed/profile: same inputs → identical output bytes.
    let artifact: OwnedFd =
        std::fs::File::open(std::env::var("RUNNE_LLAMA_TEST_GGUF").expect("path"))
            .expect("reopen fixture")
            .into();
    engine.load(&load, &config, artifact).expect("reload");
    let (second, _) = engine
        .infer([1; 16], [2; 16], [3; 16], "Say hello.")
        .expect("second run");
    let text2: String = second
        .iter()
        .filter_map(|i| match i {
            EngineItem::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(text, text2, "seeded CPU run must be deterministic");
}

#[test]
fn llama_cpu_rejects_digest_mismatch() {
    let Some((artifact, mut load)) = fixture() else {
        eprintln!("skipped: RUNNE_LLAMA_TEST_GGUF not set");
        return;
    };
    load.artifact_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
    let config = WorkerBackendConfig {
        context_max_tokens: 512,
        output_max_tokens: 8,
        gpu_layers: 0,
        threads: 2,
        seed: 1,
    };
    let mut engine = LlamaEngine::new().expect("backend");
    let err = engine
        .load(&load, &config, artifact)
        .expect_err("digest gate");
    // The engine reports the actually computed digest of the artifact.
    match err {
        runne_llama_worker::engine::EngineFailure::Native(
            WorkerErrorCode::DigestMismatch,
            actual,
        ) => assert!(actual.starts_with("sha256:"), "digest form: {actual}"),
        other => panic!("expected digest mismatch, got {other:?}"),
    }
}
