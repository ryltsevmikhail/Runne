use super::*;

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(crate) fn encode_request(
    binding: BindingV1,
    path: String,
    root: IdentityV1,
    expected: Option<VersionV1>,
    content: &[u8],
) -> Result<Vec<u8>, ()> {
    let request = match (binding, expected) {
        (binding, Some(expected)) if content.is_empty() => RequestV1::Read {
            binding,
            path,
            root,
            expected,
        },
        (binding, None) if content.len() <= MAX_CONTENT => RequestV1::CreateNew {
            binding,
            path,
            root,
            expected_absent: true,
            content_base64: STANDARD.encode(content),
        },
        _ => return Err(()),
    };
    let bytes = serde_json::to_vec(&request).map_err(|_| ())?;
    (bytes.len() <= MAX_INPUT).then_some(bytes).ok_or(())
}

#[derive(Debug)]
pub enum HelperProcessError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    InvalidOutput,
}

pub fn run() -> Result<(), HelperProcessError> {
    #[cfg(feature = "test-support")]
    super::credential_companion_test_support::assert_helper_argv_environment_clear();
    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut input)
        .map_err(HelperProcessError::Io)?;
    let root = File::open(".").map_err(HelperProcessError::Io)?;
    let output = match execute(&root, &input) {
        Ok(receipt) => serde_json::to_vec(&receipt).map_err(HelperProcessError::Serialization)?,
        Err(code) => serde_json::to_vec(&ErrorV1 {
            status: "error".to_owned(),
            version: 1,
            error: code
                .strip_prefix("effect_started_")
                .unwrap_or(code)
                .to_owned(),
            effect_started: code.starts_with("effect_started_"),
        })
        .map_err(HelperProcessError::Serialization)?,
    };
    if output.len() > 16 * 1024 {
        return Err(HelperProcessError::InvalidOutput);
    }
    std::io::stdout()
        .write_all(&output)
        .map_err(HelperProcessError::Io)?;
    Ok(())
}
