use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

const FIXTURE_CREDENTIAL: &[u8] = b"fixture-credential";

pub(crate) fn assert_helper_argv_environment_clear() {
    for argument in std::env::args_os() {
        assert_fixture_credential_absent(
            "safe-tool helper argv",
            argument.to_string_lossy().as_bytes(),
        );
    }
    for (key, value) in std::env::vars_os() {
        assert_fixture_credential_absent(
            "safe-tool helper environment key",
            key.to_string_lossy().as_bytes(),
        );
        assert_fixture_credential_absent(
            "safe-tool helper environment value",
            value.to_string_lossy().as_bytes(),
        );
    }
}

pub(crate) fn assert_receipt_and_content_clear(receipt: &[u8], content: &[u8]) {
    assert_fixture_credential_absent("authenticated helper receipt", receipt);
    assert_fixture_credential_absent("decoded helper content", content);
}

fn assert_fixture_credential_absent(sink: &str, bytes: &[u8]) {
    let standard = STANDARD.encode(FIXTURE_CREDENTIAL);
    let unpadded = standard.trim_end_matches('=');
    let url_safe = URL_SAFE_NO_PAD.encode(FIXTURE_CREDENTIAL);
    let lower_hex = hex::encode(FIXTURE_CREDENTIAL);
    let upper_hex = hex::encode_upper(FIXTURE_CREDENTIAL);
    let representations: [&[u8]; 6] = [
        FIXTURE_CREDENTIAL,
        standard.as_bytes(),
        unpadded.as_bytes(),
        url_safe.as_bytes(),
        lower_hex.as_bytes(),
        upper_hex.as_bytes(),
    ];
    assert!(
        !representations.iter().any(|pattern| {
            bytes
                .windows(pattern.len())
                .any(|window| window == *pattern)
        }),
        "{sink} contained protected fixture material"
    );
}
