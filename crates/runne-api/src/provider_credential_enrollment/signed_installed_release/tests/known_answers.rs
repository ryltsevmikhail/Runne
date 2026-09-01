use super::super::{UpdateMetadataV2, UpdateTrustRootV2};

pub(super) const RELEASE_BINDING: [u8; 32] = [
    0x0a, 0x00, 0x30, 0xf4, 0x50, 0x32, 0x6a, 0x72, 0x5e, 0x26, 0x0a, 0xdc, 0x9a, 0x9a, 0x81, 0x05,
    0x6b, 0x11, 0x5b, 0x9e, 0x2e, 0x06, 0xbc, 0xa2, 0xfa, 0x50, 0x75, 0x2f, 0x72, 0x80, 0x78, 0x1f,
];

pub(super) fn metadata() -> UpdateMetadataV2 {
    serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/signed_installed_release_v2.json"
    ))
    .unwrap()
}

pub(super) fn trust() -> UpdateTrustRootV2 {
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

fn hex_32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}
