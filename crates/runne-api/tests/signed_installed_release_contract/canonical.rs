use runne_api::{
    SignedInstalledReleaseVerificationErrorV2 as Error, UpdateMetadataV2, UpdateTrustRootV2,
    verify_exact_signed_installed_release_v2, verify_signed_update_metadata_v2,
};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("../fixtures/signed_installed_release_v2.json");
const TARGETS_SHA256: &str = "2ba962e27c38bb64abc7dbfe67dfe64760ee0fb84e4e9530b68cec854e5123e3";
const TUPLE_SHA256: &str = "cc15dcd7b26158e7931a2f7cbc01e3243523800209c81b309e738f8b41ea6a2e";
const QUALIFICATION_SHA256: &str =
    "2f2e790095684939377ae3e6991bef381ef1bd314f0f33b501c3a6164f228897";
const MANIFEST_SHA256: &str = "51884867b951d2369bb77a75ed8f89cf2ce33ec4819085d0020cd8c65e963f95";
const RELEASE_BINDING_SHA256: &str =
    "0a0030f450326a725e260adc9a9a81056b1151b9e2e06bca2fa50752f7280781";

pub(crate) fn fixture() -> &'static [u8] {
    FIXTURE
}

pub(crate) fn trust() -> UpdateTrustRootV2 {
    UpdateTrustRootV2::from_keys(
        [
            (
                "root-a",
                hex_32("43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de"),
            ),
            (
                "root-b",
                hex_32("4ed32f63bf35f0eeefcb25f28a2e1fbdc873ae2835671b0c9460f5f12e4556a8"),
            ),
            (
                "root-c",
                hex_32("884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b"),
            ),
        ],
        (
            "timestamp",
            hex_32("a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"),
        ),
        (
            "snapshot",
            hex_32("74f85cda34d1c27c4621484731e91579c3d9c6cfc0d94b281aa11e9162058aa9"),
        ),
    )
}

pub(crate) fn hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture uses lowercase hex"),
    }
}

#[test]
fn frozen_signed_release_matches_independent_known_answers() {
    let metadata: UpdateMetadataV2 = serde_json::from_slice(fixture()).expect("literal metadata");
    assert_eq!(fixture(), serde_json::to_vec(&metadata).unwrap());
    let targets = serde_json::to_vec(&metadata.targets).expect("literal targets");
    assert_eq!(targets.len(), 2_010);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&targets)),
        hex_32(TARGETS_SHA256)
    );

    let verified = verify_exact_signed_installed_release_v2(
        fixture(),
        &trust(),
        hex_32(RELEASE_BINDING_SHA256),
        100,
    )
    .expect("frozen threshold-signed release");
    let release = verified.signed_candidate();
    let tuple = release.native_enrollment_tuple();

    assert_eq!(tuple.candidate_digest(), [0xdd; 32]);
    assert_eq!(tuple.inner_tuple_digest(), hex_32(TUPLE_SHA256));
    assert_eq!(tuple.desktop_image_digest(), [0xcc; 32]);
    assert_eq!(tuple.writer_image_digest(), [0xee; 32]);
    assert_eq!(tuple.daemon_image_digest(), [0xff; 32]);
    assert_eq!(tuple.contract_digest(), [0xbb; 32]);
    assert_eq!(
        release.qualification_binding_digest(),
        hex_32(QUALIFICATION_SHA256)
    );
    assert_eq!(release.target_manifest_digest(), hex_32(MANIFEST_SHA256));
    assert_eq!(
        release.release_binding_digest(),
        hex_32(RELEASE_BINDING_SHA256)
    );
    assert_eq!(release.qualification_receipt_digest(), [0x99; 32]);
    assert_eq!(release.qualified_at_unix_seconds(), 99);
    assert_eq!(release.expires_at_unix_seconds(), 200);
    assert_eq!(
        tuple.writer_code_identity().unwrap().identifier(),
        "com.runne.writer"
    );
}

#[test]
fn exact_metadata_is_bounded_and_canonical_without_normalization() {
    assert_eq!(fixture().len(), 3_268);
    assert_ne!(fixture().last(), Some(&b'\n'));
    assert_eq!(
        verify_exact_signed_installed_release_v2(
            &[],
            &trust(),
            hex_32(RELEASE_BINDING_SHA256),
            100
        ),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(
        verify_exact_signed_installed_release_v2(
            &vec![b' '; 524_289],
            &trust(),
            hex_32(RELEASE_BINDING_SHA256),
            100
        ),
        Err(Error::MetadataTooLarge)
    );
    for malformed in [
        b"{".as_slice(),
        b"\xef\xbb\xbf{}".as_slice(),
        b"{}x".as_slice(),
    ] {
        assert_eq!(
            verify_exact_signed_installed_release_v2(
                malformed,
                &trust(),
                hex_32(RELEASE_BINDING_SHA256),
                100
            ),
            Err(Error::InvalidEncoding)
        );
    }
    let mut trailing = fixture().to_vec();
    trailing.push(b'\n');
    let mut leading = vec![b' '];
    leading.extend_from_slice(fixture());
    let reordered =
        serde_json::to_vec(&serde_json::from_slice::<serde_json::Value>(fixture()).unwrap())
            .unwrap();
    assert_ne!(reordered, fixture());
    for noncanonical in [trailing, leading, reordered] {
        assert_eq!(
            verify_exact_signed_installed_release_v2(
                &noncanonical,
                &trust(),
                hex_32(RELEASE_BINDING_SHA256),
                100
            ),
            Err(Error::NonCanonicalMetadata)
        );
    }
}

#[test]
fn duplicate_and_unknown_fields_never_enter_exact_verification() {
    let canonical = std::str::from_utf8(fixture()).unwrap();
    let duplicate = canonical.replacen(
        "{\"schemaVersion\":2,",
        "{\"schemaVersion\":2,\"schemaVersion\":2,",
        1,
    );
    let unknown = canonical.replacen(
        "{\"schemaVersion\":2,",
        "{\"unknown\":0,\"schemaVersion\":2,",
        1,
    );
    for rejected in [duplicate, unknown] {
        assert_eq!(
            verify_exact_signed_installed_release_v2(
                rejected.as_bytes(),
                &trust(),
                hex_32(RELEASE_BINDING_SHA256),
                100
            ),
            Err(Error::InvalidEncoding)
        );
    }
}

#[test]
fn exact_binding_is_external_nonzero_and_not_the_inner_tuple() {
    let metadata: UpdateMetadataV2 = serde_json::from_slice(fixture()).unwrap();
    let generic = verify_signed_update_metadata_v2(&metadata, &trust(), 100).unwrap();
    let candidate = generic.qualified_release_candidate().unwrap();
    assert_ne!(
        candidate.release_binding_digest(),
        candidate.native_enrollment_tuple().inner_tuple_digest()
    );
    for expected in [
        [0; 32],
        [7; 32],
        candidate.native_enrollment_tuple().inner_tuple_digest(),
    ] {
        assert_eq!(
            verify_exact_signed_installed_release_v2(fixture(), &trust(), expected, 100),
            Err(Error::ReleaseBindingMismatch)
        );
    }
}
