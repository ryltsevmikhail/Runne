#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
use super::NativeEnrollmentTupleError;
#[path = "measurement/opened_file.rs"]
mod opened_file;
pub(super) use opened_file::OpenedNativeEnrollmentFile;

/// Independently measured installed artifacts, not caller-supplied digests.
#[derive(Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "measured artifact fields make their digest algorithm explicit"
)]
pub struct MeasuredNativeEnrollmentArtifactsV1 {
    pub(super) desktop_sha256: String,
    pub(super) writer_sha256: String,
    pub(super) daemon_sha256: String,
    pub(super) contract_sha256: String,
}

impl MeasuredNativeEnrollmentArtifactsV1 {
    pub(in crate::updater_metadata) fn role_digests(&self) -> Option<[[u8; 32]; 4]> {
        Some([
            decode_digest(&self.desktop_sha256)?,
            decode_digest(&self.writer_sha256)?,
            decode_digest(&self.daemon_sha256)?,
            decode_digest(&self.contract_sha256)?,
        ])
    }

    pub(super) fn daemon_and_contract_digests(&self) -> (&str, &str) {
        (&self.daemon_sha256, &self.contract_sha256)
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(super) fn measure(
        desktop: &OpenedNativeEnrollmentFile,
        writer: &OpenedNativeEnrollmentFile,
        daemon: &OpenedNativeEnrollmentFile,
        contract: &OpenedNativeEnrollmentFile,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let desktop_sha256 = desktop.measure()?;
        let writer_sha256 = writer.measure()?;
        let daemon_sha256 = daemon.measure()?;
        let contract_sha256 = contract.measure()?;
        let values = [
            desktop_sha256.as_str(),
            writer_sha256.as_str(),
            daemon_sha256.as_str(),
            contract_sha256.as_str(),
        ];
        (!values
            .iter()
            .enumerate()
            .any(|(index, value)| values[..index].contains(value)))
        .then_some(Self {
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
        })
        .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_only_from_digests(
        desktop_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let values = [
            desktop_sha256.as_str(),
            writer_sha256.as_str(),
            daemon_sha256.as_str(),
            contract_sha256.as_str(),
        ];
        (values.iter().all(|value| valid_digest(value))
            && !values
                .iter()
                .enumerate()
                .any(|(index, value)| values[..index].contains(value)))
        .then_some(Self {
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
        })
        .ok_or(NativeEnrollmentTupleError::Rejected)
    }
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

#[cfg(any(test, feature = "test-support"))]
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
