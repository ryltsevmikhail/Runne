use runne_domain::id::{CommandId, IdempotencyKey};
use sha2::{Digest, Sha256};

use super::receipts::Scope;

pub(crate) struct FingerprintInput<'a> {
    pub(crate) authority: &'a str,
    pub(crate) principal: &'a str,
    pub(crate) command_id: CommandId,
    pub(crate) key: &'a IdempotencyKey,
    pub(crate) scope: Scope,
    pub(crate) related_id: Option<[u8; 16]>,
    pub(crate) expected_version: Option<u64>,
    pub(crate) display_name: Option<&'a str>,
    pub(crate) admission_digest: Option<&'a [u8; 32]>,
}

pub(crate) fn semantic_fingerprint(input: FingerprintInput<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gocode-project-workspace-command\x01");
    update_bytes(&mut digest, input.authority.as_bytes());
    update_bytes(&mut digest, input.principal.as_bytes());
    digest.update(input.command_id.as_bytes());
    update_bytes(&mut digest, input.key.as_str().as_bytes());
    digest.update([input.scope.operation as u8, input.scope.aggregate_kind]);
    digest.update(input.scope.aggregate_id);
    match input.related_id {
        Some(id) => {
            digest.update([1]);
            digest.update(id);
        }
        None => digest.update([0]),
    }
    match input.expected_version {
        Some(version) => {
            digest.update([1]);
            digest.update(version.to_be_bytes());
        }
        None => digest.update([0]),
    }
    match input.display_name {
        Some(name) => {
            digest.update([1]);
            update_bytes(&mut digest, name.as_bytes());
        }
        None => digest.update([0]),
    }
    match input.admission_digest {
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
        None => digest.update([0]),
    }
    digest.finalize().into()
}

fn update_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}
