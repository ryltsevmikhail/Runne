use rand::RngCore as _;
use runne_api::{
    BootstrapAck, RootArmRequest, RootConsumeRequest, RootIssuedProof, RootPrepared, RunBinding,
};
use runne_native_qualification::{
    PendingQualificationRunBootstrapProof, QualificationRunBootstrapExpectation,
    QualificationRunBootstrapVerifier,
};
use runne_qualification_bootstrap_policy::{
    QualificationBootstrapPolicy, RetainedQualificationBootstrapPolicy,
};
use runne_qualification_runner::{BootstrapArmed, BootstrapPreparation, QualificationReplayLedger};
use sha2::{Digest as _, Sha256};

use crate::{Error, Result, authority::Authority, executable::AdmittedExecutable, issuer};

pub struct RootState {
    policy: RetainedQualificationBootstrapPolicy,
    executable: AdmittedExecutable,
    authority: Authority,
    ledger: QualificationReplayLedger,
    verifier: QualificationRunBootstrapVerifier,
}

impl RootState {
    pub fn load() -> Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(Error);
        }
        let policy = RetainedQualificationBootstrapPolicy::load_current().map_err(|_| Error)?;
        if !policy.policy().valid_at(now()?) {
            return Err(Error);
        }
        let executable = AdmittedExecutable::load(policy.policy())?;
        let authority = Authority::load(policy.policy(), &executable)?;
        let value = Self {
            policy,
            executable,
            authority,
            ledger: QualificationReplayLedger::open_production().map_err(|_| Error)?,
            verifier: QualificationRunBootstrapVerifier::from_compiled_policy(),
        };
        value.revalidate()?;
        Ok(value)
    }

    pub const fn policy(&self) -> &QualificationBootstrapPolicy {
        self.policy.policy()
    }

    pub fn revalidate(&self) -> Result<()> {
        self.policy.revalidate().map_err(|_| Error)?;
        self.executable.revalidate(self.policy())?;
        self.authority.revalidate(self.policy())?;
        if !self.policy().valid_at(now()?) {
            return Err(Error);
        }
        Ok(())
    }

    pub fn prepare(&mut self) -> Result<RootPrepared> {
        self.revalidate()?;
        let issued_at = now()?;
        let run_not_after = issued_at
            .checked_add(self.policy().max_run_duration_seconds())
            .ok_or(Error)?
            .min(self.policy().expires_at());
        let expires_at = issued_at.checked_add(900).ok_or(Error)?.min(run_not_after);
        let offer_id = random()?;
        let preparation = BootstrapPreparation::new(
            binding(self.policy())?,
            offer_id,
            random()?,
            random()?,
            issued_at,
            expires_at,
            run_not_after,
            self.policy().max_run_duration_seconds(),
        )
        .map_err(|_| Error)?;
        self.ledger
            .prepare_bootstrap(preparation)
            .map_err(|_| Error)?;
        RootPrepared::new(offer_id, binding(self.policy())?, expires_at, run_not_after)
            .map_err(|_| Error)
    }

    pub fn arm(&mut self, request: &RootArmRequest) -> Result<RootIssuedProof> {
        self.revalidate()?;
        if request.candidate_sha256() != self.policy().candidate_sha256()
            || request.raw_v3_tuple_sha256() != self.policy().raw_v3_tuple_sha256()
            || request.profile_sha256() != self.policy().profile_sha256()
        {
            return Err(Error);
        }
        let armed = self
            .ledger
            .arm_bootstrap(request.offer_id(), request.daemon_challenge())
            .map_err(|_| Error)?;
        let unsigned = crate::issue_input::from_armed(&armed);
        self.authority.revalidate(self.policy())?;
        let proof = issuer::sign(&unsigned, self.authority.signing_key())?;
        let digest = Sha256::digest(&proof).into();
        self.ledger
            .mark_bootstrap_issued(request.offer_id(), digest)
            .map_err(|_| Error)?;
        RootIssuedProof::new(request.offer_id(), request.daemon_challenge(), proof)
            .map_err(|_| Error)
    }

    pub fn consume(&mut self, request: RootConsumeRequest) -> Result<BootstrapAck> {
        self.revalidate()?;
        let offer_id = request.offer_id();
        let challenge = request.daemon_challenge();
        let digest = Sha256::digest(request.signed_proof()).into();
        let armed = self
            .ledger
            .load_bootstrap_issued(offer_id, challenge, digest)
            .map_err(|_| Error)?;
        let expected = expectation(&armed)?;
        let pending =
            PendingQualificationRunBootstrapProof::from_signed_bytes(request.into_signed_proof())
                .map_err(|_| Error)?;
        let verified = self
            .verifier
            .verify_and_consume(pending, &expected, now()?)
            .map_err(|_| Error)?;
        self.ledger.consume_run(verified).map_err(|_| Error)?;
        self.ledger
            .mark_bootstrap_consumed(offer_id, challenge, digest)
            .map_err(|_| Error)?;
        BootstrapAck::new(
            offer_id,
            challenge,
            binding(self.policy())?,
            digest,
            armed.run_not_after(),
        )
        .map_err(|_| Error)
    }
}

pub fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error)
}

fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error)?;
    if bytes == [0; 32] {
        return Err(Error);
    }
    Ok(bytes)
}

fn binding(policy: &QualificationBootstrapPolicy) -> Result<RunBinding> {
    RunBinding::new(
        policy.workflow_run_id(),
        policy.source_revision(),
        policy.candidate_sha256(),
        policy.raw_v3_tuple_sha256(),
        policy.namespace_sha256(),
        policy.manifest_sha256(),
        policy.profile_sha256(),
    )
    .map_err(|_| Error)
}

fn expectation(armed: &BootstrapArmed) -> Result<QualificationRunBootstrapExpectation> {
    let binding = armed.binding();
    QualificationRunBootstrapExpectation::new(
        binding.candidate_sha256(),
        binding.raw_v3_tuple_sha256(),
        binding.source_revision(),
        binding.workflow_run_id(),
        binding.namespace_sha256(),
        binding.manifest_sha256(),
        binding.profile_sha256(),
        armed.context_id(),
        armed.nonce(),
        armed.challenge(),
        armed.issued_at(),
        armed.expires_at(),
        armed.run_not_after(),
        armed.max_run_duration(),
    )
    .map_err(|_| Error)
}
