//! Non-authoritative closed delivery-stage status for the provider effect boundary.
//!
//! The provider round can fail between opening its effect window and the first
//! write-ahead journal record. That failure leaves no journal row and no remote
//! artifact, so the durable trace alone cannot name the failing stage. This
//! module publishes the last fixed adapter diagnostic code to an owner-private
//! file next to the database; publication never changes admission or settlement.
use std::sync::Arc;

use runne_daemon_deepseek_effect::{DeepSeekEffectDiagnostic, DeepSeekEffectObserver};

/// Builds the observer for one database directory, if the path is usable.
pub(super) fn observer(database: &str) -> Option<Arc<dyn DeepSeekEffectObserver>> {
    let directory = std::path::Path::new(database).parent()?.to_path_buf();
    Some(Arc::new(DeliveryStatus { directory }))
}

struct DeliveryStatus {
    directory: std::path::PathBuf,
}

impl DeepSeekEffectObserver for DeliveryStatus {
    fn observe(&self, diagnostic: DeepSeekEffectDiagnostic) {
        let _ = publish(&self.directory, stage_name(diagnostic));
    }
}

#[cfg(target_os = "linux")]
fn publish(directory: &std::path::Path, stage: &'static str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::{fs::OpenOptions, io};
    if stage.len() > 48
        || !stage.starts_with("dispatch_")
        || !stage.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    {
        return Err(io::Error::other("invalid status"));
    }
    let directory_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(directory)?;
    let metadata = directory_file.metadata()?;
    if !directory.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::other("private directory required"));
    }
    let anchored =
        std::path::PathBuf::from(format!("/proc/self/fd/{}", directory_file.as_raw_fd()));
    let anchored = anchored.as_path();
    let destination = anchored.join("provider-delivery-status");
    if let Ok(meta) = destination.symlink_metadata()
        && (!meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1)
    {
        return Err(io::Error::other("private status required"));
    }
    let temporary = anchored.join(format!(".provider-delivery-{}.tmp", uuid::Uuid::now_v7()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(stage.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, &destination)?;
        directory_file.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(target_os = "linux"))]
fn publish(_: &std::path::Path, _: &'static str) -> std::io::Result<()> {
    Ok(())
}

const fn stage_name(diagnostic: DeepSeekEffectDiagnostic) -> &'static str {
    use DeepSeekEffectDiagnostic as Diagnostic;
    match diagnostic {
        Diagnostic::ReceiptRejected => "dispatch_receipt_rejected",
        Diagnostic::RequestIdRejected => "dispatch_request_id_rejected",
        Diagnostic::MaterializationStarted => "dispatch_materialization_started",
        Diagnostic::Materialized => "dispatch_materialized",
        Diagnostic::MaterializationMissing => "dispatch_materialization_missing",
        Diagnostic::MaterializationAccessDenied => "dispatch_materialization_access_denied",
        Diagnostic::AuthorizationHeaderRejected => "dispatch_authorization_header_rejected",
        Diagnostic::RequestSendStarted => "dispatch_request_send_started",
        Diagnostic::RequestSendFailed => "dispatch_request_send_failed",
        Diagnostic::ResponseStatus(_) => "dispatch_response_status",
        Diagnostic::ResponseContractSse => "dispatch_response_contract_sse",
        Diagnostic::ResponseContractJsonRejection => "dispatch_response_contract_json_rejection",
        Diagnostic::ResponseContractRejected => "dispatch_response_contract_rejected",
        Diagnostic::BodyIdleTimeout => "dispatch_body_idle_timeout",
        Diagnostic::BodyReadFailed => "dispatch_body_read_failed",
        Diagnostic::BodyChunkLimitExceeded => "dispatch_body_chunk_limit",
        Diagnostic::BodyByteLimitExceeded => "dispatch_body_byte_limit",
        Diagnostic::BodyEmpty => "dispatch_body_empty",
        Diagnostic::BodyComplete => "dispatch_body_complete",
        Diagnostic::ResponseConstructionFailed => "dispatch_response_construction_failed",
        Diagnostic::DecodeFailed(_) => "dispatch_decode_failed",
        #[cfg(feature = "linux-native-enrollment-qualification")]
        Diagnostic::DecodeDetail { .. } => "dispatch_decode_detail",
        Diagnostic::Decoded => "dispatch_decoded",
        Diagnostic::StreamStoreFailed => "dispatch_stream_store_failed",
        Diagnostic::StreamStored => "dispatch_stream_stored",
        Diagnostic::DeadlineExpired => "dispatch_deadline_expired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stage_name_is_a_closed_private_code() {
        for diagnostic in [
            DeepSeekEffectDiagnostic::ReceiptRejected,
            DeepSeekEffectDiagnostic::MaterializationMissing,
            DeepSeekEffectDiagnostic::AuthorizationHeaderRejected,
            DeepSeekEffectDiagnostic::RequestSendStarted,
            DeepSeekEffectDiagnostic::StreamStored,
        ] {
            let name = stage_name(diagnostic);
            assert!(name.starts_with("dispatch_"));
            assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
    }
}
