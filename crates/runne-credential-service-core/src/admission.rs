use runne_provider::{
    CredentialMutationGrant, CredentialRuntimeMutationAdmission, CredentialServiceDisposition,
    CredentialWriterIngressRequest,
};
use subtle::ConstantTimeEq;

use crate::backend::{CredentialBackendResult, CredentialMutationEffect, execute_mutation};

const MAX_ADMISSIONS: usize = 64;

pub struct AdmissionLedger {
    entries: Vec<Admission>,
}

struct Admission {
    owner: [u8; 32],
    request: CredentialRuntimeMutationAdmission,
    consumed: bool,
}

impl AdmissionLedger {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn arm(
        &mut self,
        owner: [u8; 32],
        request: CredentialRuntimeMutationAdmission,
        now: u64,
    ) -> Result<(), CredentialServiceDisposition> {
        self.entries
            .retain(|entry| entry.request.deadline().expires_at_unix_millis() > now);
        if self.entries.iter().any(|entry| {
            (entry.owner == owner && same_binding(&entry.request, &request))
                || same_grant_digest(&entry.request, &request)
        }) {
            return Err(CredentialServiceDisposition::Denied);
        }
        if self.entries.len() == MAX_ADMISSIONS {
            return Err(CredentialServiceDisposition::Unavailable);
        }
        self.entries.push(Admission {
            owner,
            request,
            consumed: false,
        });
        Ok(())
    }

    pub(crate) fn clear_owner(&mut self, owner: [u8; 32]) {
        self.entries.retain(|entry| entry.owner != owner);
    }

    pub(crate) fn poll(&mut self, now: u64) {
        self.entries
            .retain(|entry| entry.request.deadline().expires_at_unix_millis() > now);
    }

    pub(crate) fn deadlines(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .map(|entry| entry.request.deadline().expires_at_unix_millis())
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn consume(
        &mut self,
        owner: [u8; 32],
        request: CredentialWriterIngressRequest,
        now: u64,
        backend: impl FnOnce(CredentialMutationEffect<'_>) -> CredentialBackendResult<()>,
    ) -> Result<CredentialBackendResult<()>, CredentialServiceDisposition> {
        let (binding, grant, material) = request.into_parts();
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.owner == owner && same_binding(&entry.request, &binding))
            .ok_or(CredentialServiceDisposition::Denied)?;
        if entry.consumed
            || now < entry.request.deadline().issued_at_unix_millis()
            || now >= entry.request.deadline().expires_at_unix_millis()
            || !grant_matches(&entry.request, &grant)
        {
            return Err(CredentialServiceDisposition::Denied);
        }
        entry.consumed = true;
        let command = entry.request.command().clone();
        Ok(execute_mutation(
            backend,
            CredentialMutationEffect::new(&command, material),
        ))
    }
}

fn same_grant_digest(
    left: &CredentialRuntimeMutationAdmission,
    right: &CredentialRuntimeMutationAdmission,
) -> bool {
    let left = left.grant_digest().binding_digest().as_bytes();
    let right = right.grant_digest().binding_digest().as_bytes();
    bool::from(left.ct_eq(&right))
}

fn grant_matches(
    expected: &CredentialRuntimeMutationAdmission,
    grant: &CredentialMutationGrant,
) -> bool {
    let expected = expected.grant_digest().binding_digest().as_bytes();
    let observed = grant.digest().binding_digest().as_bytes();
    bool::from(expected.ct_eq(&observed))
}

fn same_binding(
    left: &CredentialRuntimeMutationAdmission,
    right: &CredentialRuntimeMutationAdmission,
) -> bool {
    left.command() == right.command()
        && left.installation_owner() == right.installation_owner()
        && left.epoch() == right.epoch()
        && left.session() == right.session()
        && left.runtime_generation() == right.runtime_generation()
        && left.release_binding() == right.release_binding()
        && left.sequence() == right.sequence()
        && left.correlation() == right.correlation()
        && left.deadline() == right.deadline()
        && same_grant_digest(left, right)
}
