//! Fixed-domain, canonical TLV process-intent digest.

use sha2::{Digest, Sha256};

use super::{
    PortableUtf8V1, ProcessContractError, ProcessIdentityBindingV1, ProcessIntentDigestV1,
    ProcessIntentV1,
};

const DOMAIN: &[u8] = b"runne/process-intent/v1\0";
const STDIN_CLOSED: u8 = 0;
const CANCEL_FALSE: u8 = 0;
const CANCEL_TRUE: u8 = 1;

#[derive(Default)]
pub(super) struct TlvEncoder {
    output: Vec<u8>,
    previous_tag: Option<u16>,
}

impl TlvEncoder {
    pub(super) fn checked_u32_len(length: usize) -> Result<u32, ProcessContractError> {
        u32::try_from(length).map_err(|_| ProcessContractError::DigestEncodingInvalid)
    }

    pub(super) fn field(&mut self, tag: u16, payload: &[u8]) -> Result<(), ProcessContractError> {
        if self.previous_tag.is_some_and(|previous| tag <= previous) {
            return Err(ProcessContractError::DigestEncodingInvalid);
        }
        self.append(tag, payload)
    }

    fn repeated_field(&mut self, tag: u16, payload: &[u8]) -> Result<(), ProcessContractError> {
        if self.previous_tag.is_some_and(|previous| tag < previous) {
            return Err(ProcessContractError::DigestEncodingInvalid);
        }
        self.append(tag, payload)
    }

    fn append(&mut self, tag: u16, payload: &[u8]) -> Result<(), ProcessContractError> {
        let length = Self::checked_u32_len(payload.len())?;
        self.output.extend_from_slice(&tag.to_be_bytes());
        self.output.extend_from_slice(&length.to_be_bytes());
        self.output.extend_from_slice(payload);
        self.previous_tag = Some(tag);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.output
    }
}

pub(super) fn digest_intent(
    intent: &ProcessIntentV1,
) -> Result<ProcessIntentDigestV1, ProcessContractError> {
    let mut root = TlvEncoder::default();
    root.field(1, intent.approval().bytes())?;
    root.field(2, &file(intent.executable().identity())?)?;
    root.field(3, intent.executable_policy().bytes())?;
    root.field(4, &file(intent.cwd().identity())?)?;
    root.field(5, intent.allowed_root().bytes())?;
    root.field(6, &argv(intent.argv().values())?)?;
    root.field(7, &environment(intent.environment().values())?)?;
    root.field(8, &[STDIN_CLOSED])?;
    let bounds = intent.bounds();
    root.field(9, &bounds.stdout.to_be_bytes())?;
    root.field(10, &bounds.stderr.to_be_bytes())?;
    root.field(11, &bounds.combined.to_be_bytes())?;
    root.field(12, &bounds.timeout.to_be_bytes())?;
    root.field(
        13,
        &[if bounds.cancel {
            CANCEL_TRUE
        } else {
            CANCEL_FALSE
        }],
    )?;
    root.field(14, &binding(intent.binding())?)?;
    let mut input = DOMAIN.to_vec();
    input.extend_from_slice(&root.finish());
    Ok(ProcessIntentDigestV1(Sha256::digest(input).into()))
}

fn file(
    identity: &runne_platform_ports::process::HeldFileIdentityV1,
) -> Result<Vec<u8>, ProcessContractError> {
    let version = identity.identity_version().to_be_bytes();
    let mut fields = TlvEncoder::default();
    fields.field(1, identity.token())?;
    fields.field(2, identity.canonical_identity_digest())?;
    fields.field(3, identity.content_digest())?;
    fields.field(4, identity.filesystem_identity_digest())?;
    fields.field(5, &version)?;
    Ok(fields.finish())
}

fn argv(values: &[PortableUtf8V1]) -> Result<Vec<u8>, ProcessContractError> {
    let mut fields = TlvEncoder::default();
    fields.field(1, &TlvEncoder::checked_u32_len(values.len())?.to_be_bytes())?;
    for (index, value) in values.iter().enumerate() {
        let mut item = TlvEncoder::default();
        item.field(1, &TlvEncoder::checked_u32_len(index)?.to_be_bytes())?;
        item.field(2, value.bytes())?;
        fields.repeated_field(2, &item.finish())?;
    }
    Ok(fields.finish())
}

fn environment(
    values: &std::collections::BTreeMap<String, PortableUtf8V1>,
) -> Result<Vec<u8>, ProcessContractError> {
    let mut fields = TlvEncoder::default();
    fields.field(1, &TlvEncoder::checked_u32_len(values.len())?.to_be_bytes())?;
    for (index, (name, value)) in values.iter().enumerate() {
        let mut item = TlvEncoder::default();
        item.field(1, &TlvEncoder::checked_u32_len(index)?.to_be_bytes())?;
        item.field(2, name.as_bytes())?;
        item.field(3, value.bytes())?;
        fields.repeated_field(2, &item.finish())?;
    }
    Ok(fields.finish())
}

fn binding(value: &ProcessIdentityBindingV1) -> Result<Vec<u8>, ProcessContractError> {
    let mut fields = TlvEncoder::default();
    fields.field(1, value.principal.bytes())?;
    fields.field(2, value.authority.bytes())?;
    fields.field(3, value.owner.as_bytes())?;
    fields.field(4, value.attempt.as_bytes())?;
    fields.field(5, value.session.as_bytes())?;
    fields.field(6, value.generation.as_bytes())?;
    fields.field(7, value.accounting.bytes())?;
    fields.field(8, value.sandbox.bytes())?;
    fields.field(9, value.tree.as_bytes())?;
    Ok(fields.finish())
}
