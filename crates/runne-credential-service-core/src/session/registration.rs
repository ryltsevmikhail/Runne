use std::collections::HashMap;

use runne_api::{
    CredentialServiceRegistrationAck, CredentialServiceRegistrationError,
    CredentialServiceSessionAuthenticator,
};
use runne_provider::{CredentialServiceDisposition, CredentialServiceEndpointRole};

use super::{ActiveSession, CredentialRegistrationOutcome, CredentialServiceCore};

impl CredentialServiceCore {
    /// Atomically verifies and installs a challenged Desktop registration frame.
    ///
    /// # Errors
    ///
    /// Returns a closed disposition for a wrong listener, invalid MAC, stale challenge or conflict.
    pub fn accept_registration_install(
        &mut self,
        listener_role: CredentialServiceEndpointRole,
        bytes: &[u8],
        now: u64,
    ) -> Result<
        (
            CredentialRegistrationOutcome,
            CredentialServiceRegistrationAck,
        ),
        CredentialServiceDisposition,
    > {
        if listener_role != CredentialServiceEndpointRole::Desktop {
            return Err(CredentialServiceDisposition::Denied);
        }
        self.challenges.retain(|_, expiry| *expiry > now);
        let mut planned = None;
        let accepted =
            CredentialServiceSessionAuthenticator::accept_registration_install_with_policy(
                bytes,
                now,
                |binding| {
                    let outcome = self
                        .classify_registration(binding, now)
                        .map_err(|()| CredentialServiceRegistrationError::BindingMismatch)?;
                    if outcome != CredentialRegistrationOutcome::Idempotent
                        && !self.challenges.contains_key(binding.challenge_nonce())
                    {
                        return Err(CredentialServiceRegistrationError::BindingMismatch);
                    }
                    planned = Some((binding.clone(), outcome));
                    Ok(())
                },
            )
            .map_err(|_| CredentialServiceDisposition::Denied)?;
        let (authenticator, ack) = accepted
            .complete(now)
            .map_err(|_| CredentialServiceDisposition::Denied)?;
        let (binding, outcome) = planned.ok_or(CredentialServiceDisposition::Denied)?;
        let owner = *binding.installation_owner();
        if outcome == CredentialRegistrationOutcome::Idempotent {
            let current = self
                .sessions
                .get(&owner)
                .ok_or(CredentialServiceDisposition::Denied)?;
            authenticator
                .decode_and_verify_ack_for(&current.ack.clone().into_bytes(), &binding, now)
                .map_err(|_| CredentialServiceDisposition::Denied)?;
            return Ok((outcome, current.ack.clone()));
        }
        if self.challenges.remove(binding.challenge_nonce()).is_none() {
            return Err(CredentialServiceDisposition::Denied);
        }
        self.admissions.clear_owner(owner);
        self.sessions.insert(
            owner,
            ActiveSession {
                binding,
                authenticator,
                ack: ack.clone(),
                last_sequence: 0,
                read_receipts: HashMap::new(),
            },
        );
        Ok((outcome, ack))
    }
}
