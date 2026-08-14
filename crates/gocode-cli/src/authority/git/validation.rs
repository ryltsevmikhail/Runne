//! Fixed Git object-format and digest validation helpers.

use super::super::super::CliError;

pub(super) fn oid_width(format: &str) -> Result<usize, CliError> {
    match format {
        "sha1" => Ok(40),
        "sha256" => Ok(64),
        _ => Err(CliError::AuthorityGit),
    }
}

pub(super) fn require_oid(oid: &str, width: usize) -> Result<(), CliError> {
    if oid.len() == width
        && oid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte <= b'f')
    {
        Ok(())
    } else {
        Err(CliError::AuthorityGit)
    }
}

pub(super) fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) fn parse_line(output: &[u8]) -> Result<String, CliError> {
    let line = std::str::from_utf8(output).map_err(|_| CliError::AuthorityGit)?;
    let Some(line) = line.strip_suffix('\n') else {
        return Err(CliError::AuthorityGit);
    };
    if line.is_empty() || line.contains('\n') {
        Err(CliError::AuthorityGit)
    } else {
        Ok(line.into())
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_formats_and_malformed_or_uppercase_object_ids() {
        assert!(matches!(oid_width("sha512"), Err(CliError::AuthorityGit)));
        assert!(matches!(
            require_oid(&"A".repeat(40), 40),
            Err(CliError::AuthorityGit)
        ));
        assert!(matches!(
            require_oid(&"g".repeat(40), 40),
            Err(CliError::AuthorityGit)
        ));
    }
}
