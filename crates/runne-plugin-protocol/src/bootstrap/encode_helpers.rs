// ── Encode helpers ────────────────────────────────────────────────────────

fn encode_host_identity(enc: &mut CborEncoder, id: &HostExecutionIdentity) {
    match id {
        HostExecutionIdentity::Plugin(pi) => {
            enc.write_map_header(1);
            enc.write_unsigned(1);
            enc.write_text_string(pi.as_str());
        }
        HostExecutionIdentity::Migration(mi) => {
            enc.write_map_header(1);
            enc.write_unsigned(2);
            enc.write_text_string(mi.as_str());
        }
    }
}

fn decode_host_identity(dec: &mut CborDecoder) -> Result<HostExecutionIdentity, DecodeError> {
    let map_len = dec.read_map_header(2)?;
    let mut id = None;
    for _ in 0..map_len {
        let key = dec.read_unsigned(2)?;
        match key {
            1 => {
                let s = dec.read_text_string(256)?;
                id = Some(HostExecutionIdentity::Plugin(
                    PluginIdentity::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })?,
                ));
            }
            2 => {
                let s = dec.read_text_string(256)?;
                id = Some(HostExecutionIdentity::Migration(
                    MigrationIdentity::new(s)
                        .map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })?,
                ));
            }
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }
    id.ok_or(DecodeError::MissingRequiredField { key: 1 })
}

fn encode_profile_ref(enc: &mut CborEncoder, prof: &crate::profile::ProtocolProfileRef) {
    enc.write_map_header(2);
    enc.write_unsigned(1);
    enc.write_text_string(prof.profile_id().as_str());
    enc.write_unsigned(2);
    enc.write_byte_string(prof.profile_digest().as_bytes());
}

fn encode_package_digest(enc: &mut CborEncoder, pd: &PackageDigest) {
    enc.write_map_header(2);
    enc.write_unsigned(1);
    enc.write_unsigned(match pd.algorithm() {
        DigestAlgorithm::Sha256 => 1,
    });
    enc.write_unsigned(2);
    enc.write_byte_string(pd.as_bytes());
}

fn reject_reason_code(r: &NegotiationRejectReason) -> u64 {
    match r {
        NegotiationRejectReason::ProfileNotSupported => 1,
        NegotiationRejectReason::DigestMismatch => 2,
        NegotiationRejectReason::IdentityRejected => 3,
        NegotiationRejectReason::VersionIncompatible => 4,
    }
}

fn reject_reason_from_code(code: u64) -> Option<NegotiationRejectReason> {
    match code {
        1 => Some(NegotiationRejectReason::ProfileNotSupported),
        2 => Some(NegotiationRejectReason::DigestMismatch),
        3 => Some(NegotiationRejectReason::IdentityRejected),
        4 => Some(NegotiationRejectReason::VersionIncompatible),
        _ => None,
    }
}
