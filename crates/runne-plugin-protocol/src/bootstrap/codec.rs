// CBOR message type IDs:
// 1 = HostHello, 2 = PluginHello, 3 = NegotiationRejected,
// 4 = ProfileSelected, 5 = SelectionAcknowledged

impl DeterministicCodec for BootstrapMessage {
    const MESSAGE_TYPE_ID: u32 = 0; // BootstrapMessage is a wrapper

    fn encode(&self, enc: &mut CborEncoder) -> Result<(), EncodeError> {
        match self {
            Self::HostHello(m) => {
                enc.write_map_header(4);
                // Key ordering (bytewise lexicographic): 1,2,3,4
                // Key 1: nonce
                enc.write_unsigned(1);
                enc.write_byte_string(m.nonce.as_bytes());
                // Key 2: host_identity
                enc.write_unsigned(2);
                encode_host_identity(enc, &m.host_identity);
                // Key 3: supported_profiles
                enc.write_unsigned(3);
                enc.write_array_header(m.supported_profiles.len() as u64);
                for prof in m.supported_profiles.as_slice() {
                    encode_profile_ref(enc, prof);
                }
                // Key 4: negotiation_snapshot
                enc.write_unsigned(4);
                enc.write_byte_string(m.negotiation_snapshot.as_bytes());
                Ok(())
            }
            Self::PluginHello(m) => {
                enc.write_map_header(11);
                // Keys sorted: 1,2,3,4,5,6,7,8,9,10,11
                enc.write_unsigned(1);
                enc.write_byte_string(m.host_nonce.as_bytes());
                enc.write_unsigned(2);
                enc.write_byte_string(m.plugin_nonce.as_bytes());
                enc.write_unsigned(3);
                encode_host_identity(enc, &m.host_identity);
                enc.write_unsigned(4);
                enc.write_text_string(m.package_id.as_str());
                enc.write_unsigned(5);
                encode_package_digest(enc, &m.package_digest);
                enc.write_unsigned(6);
                enc.write_text_string(m.package_version.as_str());
                enc.write_unsigned(7);
                enc.write_byte_string(m.manifest_digest.as_bytes());
                enc.write_unsigned(8);
                encode_host_identity(enc, &m.plugin_identity);
                enc.write_unsigned(9);
                enc.write_text_string(m.target_identity.as_str());
                enc.write_unsigned(10);
                enc.write_array_header(m.supported_profiles.len() as u64);
                for prof in m.supported_profiles.as_slice() {
                    encode_profile_ref(enc, prof);
                }
                // Key 11: entrypoint
                enc.write_unsigned(11);
                enc.write_text_string(m.entrypoint.as_str());
                Ok(())
            }
            Self::NegotiationRejected(m) => {
                enc.write_map_header(1);
                enc.write_unsigned(1);
                enc.write_unsigned(reject_reason_code(&m.reason));
                Ok(())
            }
            Self::ProfileSelected(m) => {
                enc.write_map_header(5);
                enc.write_unsigned(1);
                enc.write_byte_string(m.host_nonce.as_bytes());
                enc.write_unsigned(2);
                enc.write_byte_string(m.plugin_nonce.as_bytes());
                enc.write_unsigned(3);
                enc.write_byte_string(m.session_id.as_bytes());
                enc.write_unsigned(4);
                enc.write_text_string(m.profile_id.as_str());
                enc.write_unsigned(5);
                enc.write_byte_string(m.profile_digest.as_bytes());
                Ok(())
            }
            Self::SelectionAcknowledged(m) => {
                enc.write_map_header(5);
                enc.write_unsigned(1);
                enc.write_byte_string(m.host_nonce.as_bytes());
                enc.write_unsigned(2);
                enc.write_byte_string(m.plugin_nonce.as_bytes());
                enc.write_unsigned(3);
                enc.write_byte_string(m.session_id.as_bytes());
                enc.write_unsigned(4);
                enc.write_text_string(m.profile_id.as_str());
                enc.write_unsigned(5);
                enc.write_byte_string(m.profile_digest.as_bytes());
                Ok(())
            }
        }
    }

    fn decode(_type_id: u32, dec: &mut CborDecoder) -> Result<Self, DecodeError> {
        // Dispatch by canonical map length. Selection acknowledgement carries
        // a mandatory direction marker and therefore cannot reflect selection.
        let map_len = dec.read_map_header(64)?;
        match map_len {
            1 => decode_negotiation_rejected(dec),
            4 => decode_host_hello(dec),
            5 => decode_profile_selected(dec),
            11 => decode_plugin_hello(dec),
            _ => Err(DecodeError::UnknownMessageType {
                type_id: map_len as u32,
            }),
        }
    }
}
