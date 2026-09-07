//! Golden fixture (Plan Task 17 Step 4): the committed canonical
//! manifest bytes in docs/golden/local-engine/builder/ must be exactly
//! reproduced by the current builder — any drift is a release-worthy
//! contract change.

mod builder_common;

use builder_common::{full_user, gguf_with_metadata};
use runne_local_model::BUILDER_CONTRACT_VERSION;
use std::io::Cursor;

#[test]
fn golden_manifest_is_reproduced_byte_for_byte() {
    let golden_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/golden/local-engine/builder/golden-manifest.json");
    let golden = std::fs::read(&golden_path).expect("golden fixture present");
    // The committed file ends with a newline from the CLI; strip it
    // for the byte comparison.
    let golden = match golden.strip_suffix(b"\n") {
        Some(g) => g.to_vec(),
        None => golden,
    };
    let (mut r, u) = (Cursor::new(gguf_with_metadata()), full_user());
    let built = runne_local_model::build_candidate_manifest(&mut r, &u, BUILDER_CONTRACT_VERSION)
        .expect("build");
    assert_eq!(built.canonical_bytes, golden, "golden drift detected");
}
