type TerminalPayload = (
    String,
    u8,
    Option<String>,
    Option<String>,
    Option<ProviderUsage>,
    u8,
);

fn encode_terminal_payload(
    artifact: &ProviderRemoteTerminalArtifact,
) -> Result<Zeroizing<Vec<u8>>, ProviderRecoveryError> {
    let (status, code, reason, usage) = match artifact.status() {
        ProviderRemoteResponseStatus::Completed { usage } => (1, None, None, *usage),
        ProviderRemoteResponseStatus::Failed { code, usage } => (2, code.clone(), None, *usage),
        ProviderRemoteResponseStatus::Incomplete { reason, usage } => {
            (3, None, reason.clone(), *usage)
        }
        ProviderRemoteResponseStatus::Cancelled { usage } => (5, None, None, *usage),
        ProviderRemoteResponseStatus::Pending | ProviderRemoteResponseStatus::Unknown => {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
    };
    let value: TerminalPayload = (
        artifact.response_id().as_str().to_owned(),
        status,
        artifact.output_text().map(str::to_owned),
        code.or(reason),
        usage,
        publication_code(artifact.publication_disposition()),
    );
    let bytes = serde_json::to_vec(&value).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
    if bytes.is_empty() || bytes.len() > 131_072 {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    Ok(Zeroizing::new(bytes))
}

fn terminal_disposition(
    status: &ProviderRemoteResponseStatus,
) -> Result<ProviderRemoteTerminalDisposition, ProviderRecoveryError> {
    match status {
        ProviderRemoteResponseStatus::Completed { .. } => {
            Ok(ProviderRemoteTerminalDisposition::Completed)
        }
        ProviderRemoteResponseStatus::Failed { .. } => {
            Ok(ProviderRemoteTerminalDisposition::Failed)
        }
        ProviderRemoteResponseStatus::Incomplete { .. } => {
            Ok(ProviderRemoteTerminalDisposition::Incomplete)
        }
        ProviderRemoteResponseStatus::Cancelled { .. } => {
            Ok(ProviderRemoteTerminalDisposition::Cancelled)
        }
        ProviderRemoteResponseStatus::Pending | ProviderRemoteResponseStatus::Unknown => {
            Err(ProviderRecoveryError::InvalidIdentity)
        }
    }
}

fn decode_terminal_payload(
    payload: &[u8],
    expected_id: &[u8],
    expected_digest: [u8; 32],
    expected_status: ProviderRemoteTerminalDisposition,
) -> Result<Option<ProviderRemoteTerminalArtifact>, ProviderRecoveryError> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
    let values = value
        .as_array()
        .ok_or(ProviderRecoveryError::InvalidIdentity)?;
    if !(values.len() == 5 || values.len() == 6) {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    let response_id = json_string(&values[0])?;
    let status = json_u8(&values[1])?;
    let mut output = json_option_string(&values[2])?;
    let detail = json_option_string(&values[3])?;
    let usage: Option<ProviderUsage> = serde_json::from_value(values[4].clone())
        .map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
    let publication = if values.len() == 6 {
        decode_publication(json_u8(&values[5])?)?
    } else {
        output = None;
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::Uncertain(
                runne_provider::ScannerUncertainReason::RedactionScannerUnavailable,
            ),
        )
    };
    if response_id.as_bytes() != expected_id
        || <[u8; 32]>::from(sha2::Sha256::digest(response_id.as_bytes())) != expected_digest
        || status != expected_status.code() as u8
    {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    let status = match expected_status {
        ProviderRemoteTerminalDisposition::Completed => {
            ProviderRemoteResponseStatus::Completed { usage }
        }
        ProviderRemoteTerminalDisposition::Failed => ProviderRemoteResponseStatus::Failed {
            code: detail,
            usage,
        },
        ProviderRemoteTerminalDisposition::Incomplete => ProviderRemoteResponseStatus::Incomplete {
            reason: detail,
            usage,
        },
        ProviderRemoteTerminalDisposition::Cancelled => {
            ProviderRemoteResponseStatus::Cancelled { usage }
        }
    };
    let response_id = runne_provider::RemoteResponseId::new(response_id)?;
    ProviderRemoteTerminalArtifact::new_with_publication_disposition(
        response_id,
        status,
        output,
        publication,
    )
    .map(Some)
}

fn publication_code(value: runne_provider::ProviderRemotePublicationDisposition) -> u8 {
    use runne_provider::{
        ProviderRemotePublicationDisposition as P, ScannerTerminalDisposition as S,
        ScannerUncertainReason as U,
    };
    match value {
        P::Allowed => 0,
        P::Rejected(S::Uncertain(U::SecretDetected)) => 1,
        P::Rejected(S::Uncertain(U::CredentialMatcherUnavailable)) => 2,
        P::Rejected(S::Uncertain(U::RedactionScannerUnavailable)) => 3,
        P::Rejected(S::Uncertain(U::CheckpointSecretStateUnavailable)) => 4,
        P::Rejected(S::OutputLimitExceeded) => 5,
        P::Rejected(S::Completed) => 6,
    }
}

fn decode_publication(
    value: u8,
) -> Result<runne_provider::ProviderRemotePublicationDisposition, ProviderRecoveryError> {
    use runne_provider::{
        ProviderRemotePublicationDisposition as P, ScannerTerminalDisposition as S,
        ScannerUncertainReason as U,
    };
    Ok(match value {
        0 => P::Allowed,
        1 => P::Rejected(S::Uncertain(U::SecretDetected)),
        2 => P::Rejected(S::Uncertain(U::CredentialMatcherUnavailable)),
        3 => P::Rejected(S::Uncertain(U::RedactionScannerUnavailable)),
        4 => P::Rejected(S::Uncertain(U::CheckpointSecretStateUnavailable)),
        5 => P::Rejected(S::OutputLimitExceeded),
        _ => return Err(ProviderRecoveryError::InvalidIdentity),
    })
}

fn json_string(value: &serde_json::Value) -> Result<String, ProviderRecoveryError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(ProviderRecoveryError::InvalidIdentity)
}

fn json_u8(value: &serde_json::Value) -> Result<u8, ProviderRecoveryError> {
    value
        .as_u64()
        .and_then(|number| u8::try_from(number).ok())
        .ok_or(ProviderRecoveryError::InvalidIdentity)
}

fn json_option_string(value: &serde_json::Value) -> Result<Option<String>, ProviderRecoveryError> {
    if value.is_null() {
        Ok(None)
    } else {
        json_string(value).map(Some)
    }
}

fn remote_terminal_aad(
    binding: &runne_application::provider::ProviderRemoteAttemptBinding,
    key: ProviderJournalKeyBinding,
    response_digest: [u8; 32],
    disposition: ProviderRemoteTerminalDisposition,
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(REMOTE_TERMINAL_AAD);
    aad.extend_from_slice(binding.taskrun_id.as_bytes());
    aad.extend_from_slice(binding.taskrun_attempt_id.as_bytes());
    aad.extend_from_slice(binding.dispatch_attempt_id.as_bytes());
    push_string(&mut aad, &binding.provider_id);
    push_string(&mut aad, &binding.credential_realm);
    push_string(&mut aad, &binding.profile_id);
    aad.extend_from_slice(&binding.profile_digest);
    aad.extend_from_slice(&binding.pricing_digest);
    aad.extend_from_slice(&binding.semantic_digest);
    aad.extend_from_slice(&binding.prepared_digest);
    aad.extend_from_slice(&binding.request_digest);
    aad.extend_from_slice(&binding.runtime_authority_id);
    aad.extend_from_slice(&binding.database_generation.to_be_bytes());
    aad.extend_from_slice(&binding.runtime_generation.to_be_bytes());
    aad.extend_from_slice(&binding.fencing_token.to_be_bytes());
    aad.extend_from_slice(&key.key_id());
    aad.extend_from_slice(&key.key_version().to_be_bytes());
    aad.extend_from_slice(&response_digest);
    aad.push(disposition.code() as u8);
    aad
}

#[cfg(test)]
mod remote_codec_tests {
    use super::*;
    use runne_provider::{
        ProviderRemotePublicationDisposition as Publication, RemoteResponseId,
        ScannerTerminalDisposition as Scanner, ScannerUncertainReason as Uncertain,
    };

    #[test]
    fn new_payload_keeps_publication_separate_and_legacy_payload_fails_closed() {
        let id = RemoteResponseId::new("resp_snapshot_codec").unwrap();
        let status = ProviderRemoteResponseStatus::Completed { usage: None };
        let safe = ProviderRemoteTerminalArtifact::new_with_publication_disposition(
            id.clone(),
            status.clone(),
            Some("exact full snapshot".into()),
            Publication::Allowed,
        )
        .unwrap();
        let encoded = encode_terminal_payload(&safe).unwrap();
        let digest = sha2::Sha256::digest(id.as_str().as_bytes()).into();
        let decoded = decode_terminal_payload(
            &encoded,
            id.as_str().as_bytes(),
            digest,
            ProviderRemoteTerminalDisposition::Completed,
        )
        .unwrap()
        .unwrap();
        assert_eq!(decoded.output_text(), Some("exact full snapshot"));
        assert_eq!(decoded.publication_disposition(), Publication::Allowed);

        let legacy = serde_json::to_vec(&(
            id.as_str(),
            1_u8,
            Some("old unproven output"),
            Option::<String>::None,
            Option::<ProviderUsage>::None,
        ))
        .unwrap();
        let decoded = decode_terminal_payload(
            &legacy,
            id.as_str().as_bytes(),
            digest,
            ProviderRemoteTerminalDisposition::Completed,
        )
        .unwrap()
        .unwrap();
        assert_eq!(decoded.status(), &status);
        assert_eq!(decoded.output_text(), None);
        assert_eq!(
            decoded.publication_disposition(),
            Publication::Rejected(Scanner::Uncertain(Uncertain::RedactionScannerUnavailable)),
        );
    }
}
