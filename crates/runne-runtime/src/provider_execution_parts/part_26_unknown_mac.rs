fn push_unknown_frame(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn encode_unknown_source_binding(source: &ProviderUnknownTerminalOriginalBinding) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(b"GOCODE_PROVIDER_UNKNOWN_SOURCE_BINDING_V1\0");
    bytes.extend_from_slice(&source.runtime_authority_id);
    push_unknown_frame(&mut bytes, source.writer_owner_id.as_bytes());
    bytes.extend_from_slice(&source.writer_lease_digest);
    bytes.extend_from_slice(&source.authority_revision.to_be_bytes());
    encode_optional_digest(&mut bytes, source.grant_digest);
    bytes.extend_from_slice(&source.database_generation.to_be_bytes());
    bytes.extend_from_slice(&source.runtime_generation.to_be_bytes());
    bytes.extend_from_slice(source.dispatch_attempt_id.as_bytes());
    bytes.extend_from_slice(source.taskrun_id.as_bytes());
    bytes.extend_from_slice(source.execution_attempt_id.as_bytes());
    bytes.extend_from_slice(source.conversation_id.as_bytes());
    push_unknown_frame(&mut bytes, source.principal_id.as_bytes());
    push_unknown_frame(&mut bytes, source.provider_id.as_bytes());
    push_unknown_frame(&mut bytes, source.provider_idempotency_key.as_bytes());
    for digest in [
        source.request_digest,
        source.begin_receipt_digest,
        source.started_receipt_digest,
    ] {
        bytes.extend_from_slice(&digest);
    }
    encode_optional_digest(&mut bytes, source.claim_receipt_digest);
    for digest in [
        source.admission_digest,
        source.committed_effect_digest,
        source.taskrun_history_digest,
        source.conversation_history_digest,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&source.taskrun_stream_version.to_be_bytes());
    bytes.extend_from_slice(&source.conversation_stream_version.to_be_bytes());
    bytes.extend_from_slice(&source.profile_digest);
    bytes.extend_from_slice(&source.pricing_revision_digest);
    push_unknown_frame(&mut bytes, source.admission_currency.as_bytes());
    bytes.push(digest_version_code(source.call_digest_version));
    bytes.extend_from_slice(&source.fencing_token.to_be_bytes());
    bytes.push(u8::from(source.publication_allowed));
    for reserve in source.reservations {
        bytes.extend_from_slice(&reserve.reservation_id);
        bytes.push(reserve.dimension);
        bytes.extend_from_slice(&reserve.reserved_amount.to_be_bytes());
        match reserve.settled_amount {
            Some(amount) => {
                bytes.push(1);
                bytes.extend_from_slice(&amount.to_be_bytes());
            }
            None => bytes.push(0),
        }
        bytes.push(u8::from(reserve.held));
    }
    bytes
}

fn encode_optional_digest(target: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(digest) => {
            target.push(1);
            target.extend_from_slice(&digest);
        }
        None => target.push(0),
    }
}

const fn digest_version_code(version: ProviderCallDigestVersion) -> u8 {
    match version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    }
}

const fn unknown_reason_code(reason: ProviderUnknownAccountingReason) -> u8 {
    match reason {
        ProviderUnknownAccountingReason::UsageUnavailable => 1,
        ProviderUnknownAccountingReason::PricingUnavailable => 2,
        ProviderUnknownAccountingReason::PricingInvalid => 3,
        ProviderUnknownAccountingReason::CurrencyMismatch => 4,
    }
}
