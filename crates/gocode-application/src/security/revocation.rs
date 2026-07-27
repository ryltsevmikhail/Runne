//! In-memory проекция revocation и authorization epoch.

use std::collections::HashSet;

use gocode_domain::security::{AuthEpoch, GrantId};

use super::error::SecurityError;

#[derive(Debug, Clone)]
pub struct RevocationManager {
    epoch: AuthEpoch,
    revoked: HashSet<GrantId>,
}

impl Default for RevocationManager {
    fn default() -> Self {
        Self::new(AuthEpoch::INITIAL)
    }
}

impl RevocationManager {
    pub fn new(epoch: AuthEpoch) -> Self {
        Self {
            epoch,
            revoked: HashSet::new(),
        }
    }

    pub fn current_epoch(&self) -> AuthEpoch {
        self.epoch
    }

    pub fn advance_epoch(&mut self) -> Result<AuthEpoch, SecurityError> {
        self.epoch = self.epoch.next();
        Ok(self.epoch)
    }

    pub fn revoke_grant(&mut self, grant_id: GrantId) -> Result<AuthEpoch, SecurityError> {
        if self.revoked.insert(grant_id) {
            self.advance_epoch()
        } else {
            Ok(self.epoch)
        }
    }

    pub fn is_revoked(&self, grant_id: GrantId) -> bool {
        self.revoked.contains(&grant_id)
    }

    pub fn validate_epoch(&self, epoch: AuthEpoch) -> Result<(), SecurityError> {
        if epoch == self.epoch {
            Ok(())
        } else {
            Err(SecurityError::StaleAuthEpoch)
        }
    }
}
