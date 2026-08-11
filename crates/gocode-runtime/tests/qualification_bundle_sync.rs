//! Bundle contract pinning: the published bundle hash, both capability sets,
//! and the ordered capability digest must stay reproducible from committed
//! artifacts (matrix row 21 / security invariant 3).

use gocode_runtime::bundle::{
    PUBLISHED_BUNDLE_HASH, PUBLISHED_RUNTIME_CAPABILITIES, RUNTIME_CAPABILITY_CATALOG,
};
use sha2::{Digest, Sha256};

const BUNDLE_JSON_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/gocode-ui-client-1/bundle.json"
);

/// Digest of `PUBLISHED_RUNTIME_CAPABILITIES` computed with the domain and
/// framing of `crates/platform-desktop/src/protected_runtime_parts/port_10.rs`
/// at the pinned base SHA; pins reproducibility of `ordered_capability_digest`
/// without any external source.
const EXPECTED_CAPABILITY_DIGEST: &str =
    "259e7e6a46aa8998ebb93964acd4b616cfe8fade2786fb3fcdd85a3d3546d551";

#[test]
fn bundle_json_sha256_matches_published_hash() {
    let bytes = std::fs::read(BUNDLE_JSON_PATH).expect("committed bundle.json must be readable");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    assert_eq!(hex::encode(hasher.finalize()), PUBLISHED_BUNDLE_HASH);
}

#[test]
fn operational_telemetry_capability_is_published_and_catalogued() {
    assert!(PUBLISHED_RUNTIME_CAPABILITIES.contains(&"runtime.operational-telemetry.v1"));
    assert!(RUNTIME_CAPABILITY_CATALOG.contains(&"runtime.operational-telemetry.v1"));
}

#[test]
fn published_capabilities_equal_catalog_exact_order() {
    // Both sets are pinned to the same committed bundle.json: exact order and
    // content must stay identical.
    assert_eq!(PUBLISHED_RUNTIME_CAPABILITIES, RUNTIME_CAPABILITY_CATALOG);
}

#[test]
fn ordered_capability_digest_is_deterministic_and_pinned() {
    let first = ordered_capability_digest(PUBLISHED_RUNTIME_CAPABILITIES);
    let second = ordered_capability_digest(PUBLISHED_RUNTIME_CAPABILITIES);
    assert_eq!(first, second, "digest must be deterministic");
    assert_eq!(hex::encode(first), EXPECTED_CAPABILITY_DIGEST);
}

/// Recomputes the ordered capability digest with the exact domain and framing
/// of `port_10.rs::ordered_capability_digest`.
fn ordered_capability_digest(capabilities: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/local-runtime/capability-digest/v1\0");
    hasher.update(
        u32::try_from(capabilities.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for capability in capabilities {
        let bytes = capability.as_bytes();
        hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}
