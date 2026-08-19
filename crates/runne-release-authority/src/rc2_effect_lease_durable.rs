//! Canonical protected-file persistence for the fixture-only RC2 effect ledger.
#![allow(clippy::missing_errors_doc, clippy::redundant_pub_crate)] // Internal durable codec.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    EffectLeaseError, FixtureRc2EffectLeaseLedger, FixtureRc2SigningAuthorization,
    FixtureRc2SigningDispatchLease, FixtureRc2SigningDispatchLeases,
    Rc2SigningBackendReadbackFixture, Rc2SigningEffectClaim,
};

#[path = "rc2_effect_lease_durable_codec.rs"]
mod codec;
pub(crate) use codec::{decode_ledger, encode_ledger};

const SCHEMA: &str = "runne.release.rc2-effect-lease-ledger/1";

/// File-backed fixture ledger. Its guarded transaction persists reservation state before dispatch.
#[allow(dead_code)] // Global durable authority consumes the codec; standalone fixture is retained for recovery tests.
pub struct DurableFixtureRc2EffectLeaseLedger {
    path: PathBuf,
    _lease: crate::store_durable_lease::Lease,
    ledger: FixtureRc2EffectLeaseLedger,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerWire {
    schema_version: String,
    claims: Vec<ClaimWire>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimWire {
    authority_instance: String,
    namespace: String,
    promotion: String,
    revision: u64,
    authorization: String,
    workflow: String,
    signer: String,
    runner: String,
    slots: Vec<SlotWire>,
    generation: u64,
    valid_from: u64,
    expires_at: u64,
    epoch: u64,
    states: Vec<String>,
    reconciliations: Vec<u8>,
    consumed_commitment: Option<String>,
    effect_evidence: Vec<RawEvidenceWire>,
    native_evidence: Vec<RawEvidenceWire>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawEvidenceWire {
    slot: String,
    raw: String,
    signature: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SlotWire {
    slot: String,
    digest: String,
    length: u64,
}

#[allow(dead_code)] // See the type-level durable fixture compatibility note.
impl DurableFixtureRc2EffectLeaseLedger {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, EffectLeaseError> {
        let lease = crate::store_durable_lease::Lease::acquire(path.as_ref())
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        let this = Self {
            path: path.as_ref().into(),
            _lease: lease,
            ledger: FixtureRc2EffectLeaseLedger::default(),
        };
        this.save_new()?;
        Ok(this)
    }

    pub fn reopen(path: impl AsRef<Path>) -> Result<Self, EffectLeaseError> {
        let lease = crate::store_durable_lease::Lease::acquire(path.as_ref())
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        crate::store_durable_file::safe_file(path.as_ref())
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        let mut bytes = Vec::new();
        File::open(path.as_ref())
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?
            .read_to_end(&mut bytes)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        Ok(Self {
            path: path.as_ref().into(),
            _lease: lease,
            ledger: decode_ledger(&bytes)?,
        })
    }

    pub fn reserve(
        &mut self,
        authorization: &FixtureRc2SigningAuthorization,
        now: u64,
        epoch: u64,
    ) -> Result<FixtureRc2SigningDispatchLeases, EffectLeaseError> {
        let lease = self.ledger.reserve(authorization, now, epoch)?;
        self.save()?;
        Ok(lease)
    }

    pub fn recover(
        &self,
        authorization: &FixtureRc2SigningAuthorization,
    ) -> Result<FixtureRc2SigningDispatchLeases, EffectLeaseError> {
        self.ledger.recover(authorization)
    }

    pub fn dispatch(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
        now: u64,
        epoch: u64,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let lease = self.ledger.dispatch(lease, now, epoch)?;
        self.save()?;
        Ok(lease)
    }

    pub fn uncertain(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let lease = self.ledger.uncertain(lease)?;
        self.save()?;
        Ok(lease)
    }

    pub fn reconcile(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
        readback: Rc2SigningBackendReadbackFixture,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let lease = self.ledger.reconcile(lease, readback)?;
        self.save()?;
        Ok(lease)
    }

    #[must_use]
    pub fn claims(&self) -> Vec<Rc2SigningEffectClaim> {
        self.ledger.claims()
    }

    fn save_new(&self) -> Result<(), EffectLeaseError> {
        let bytes = encode_ledger(&self.ledger)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.path)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        crate::store_durable_file::safe_file(&self.path)
            .and_then(|()| crate::store_durable_file::sync_parent(&self.path))
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)
    }

    fn save(&self) -> Result<(), EffectLeaseError> {
        let bytes = encode_ledger(&self.ledger)?;
        crate::store_durable_file::safe_file(&self.path)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        let temp = crate::store_durable_file::temp_file(&self.path, &bytes)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        fs::rename(temp, &self.path).map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        crate::store_durable_file::safe_file(&self.path)
            .and_then(|()| crate::store_durable_file::sync_parent(&self.path))
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)
    }
}
