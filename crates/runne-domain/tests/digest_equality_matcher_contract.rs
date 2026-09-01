use std::path::Path;

use runne_domain::DigestEqualityMatcherV1;

fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)).unwrap()
}

#[test]
fn matcher_accepts_only_the_exact_digest_and_rejects_every_byte_mutation() {
    let expected = core::array::from_fn(|index| u8::try_from(index).unwrap());
    let matcher = DigestEqualityMatcherV1::from_expected(expected);

    assert!(matcher.matches(&expected));
    for index in 0..expected.len() {
        let mut candidate = expected;
        candidate[index] ^= 0x80;
        assert!(!matcher.matches(&candidate), "accepted mutation at {index}");
    }
}

#[test]
fn matcher_source_is_fixed_work_and_has_no_escape_or_authority_surface() {
    let source = read("src/digest_equality_matcher.rs");

    assert!(source.contains("pub struct DigestEqualityMatcherV1"));
    assert!(source.contains("expected: [u8; 32]"));
    assert!(source.contains("core::iter::zip(&self.expected, candidate)"));
    assert!(source.contains("difference |= expected ^ candidate"));
    assert!(source.contains("difference == 0"));
    for forbidden in [
        "#[derive(",
        "impl Clone",
        "impl Copy",
        "impl Debug",
        "impl Default",
        "impl Hash",
        "impl Ord",
        "Serialize",
        "Deserialize",
        "AsFd",
        "AsRawFd",
        "IntoRawFd",
        "pub fn expected",
        "pub fn digest",
        "pub fn bytes",
        "pub fn raw",
        "pub fn from_parts",
        "impl From<",
        "impl Into<",
        "pub fn admit",
        "pub fn mint",
        "pub fn into_authority",
        "pub trait",
    ] {
        assert!(
            !source.contains(forbidden),
            "matcher exposes forbidden surface: {forbidden}"
        );
    }
}

#[test]
fn matcher_has_one_selective_hidden_root_export() {
    let facade = read("src/lib.rs");

    assert!(facade.contains("mod digest_equality_matcher;"));
    let export = "#[doc(hidden)]\npub use digest_equality_matcher::DigestEqualityMatcherV1;";
    assert!(facade.contains(export));
    assert!(!facade.contains("pub mod digest_equality_matcher;"));
    assert_eq!(facade.matches(export).count(), 1);
}
