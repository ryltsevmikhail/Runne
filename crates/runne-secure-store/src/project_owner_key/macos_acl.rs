//! Exact code-signing identity gate for the dedicated owner-key access group.

use std::str::FromStr;

use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

use crate::{
    PROJECT_OWNER_KEYCHAIN_ACCESS_GROUP, StoreStatus,
    project_owner_key::identity_policy::valid_designated_requirement,
};

/// Independently configured identity allowed to operate the owner-key items.
pub struct CodeSignIdentity {
    designated_requirement: String,
}

impl CodeSignIdentity {
    /// Bind the backend to one non-empty designated requirement and access group.
    ///
    /// # Errors
    ///
    /// Returns [`StoreStatus::Denied`] unless the dedicated access group is exact.
    pub fn new(
        designated_requirement: impl Into<String>,
        access_group: impl Into<String>,
    ) -> Result<Self, StoreStatus> {
        let designated_requirement = designated_requirement.into();
        let access_group = access_group.into();
        if !valid_designated_requirement(&designated_requirement)
            || access_group != PROJECT_OWNER_KEYCHAIN_ACCESS_GROUP
        {
            return Err(StoreStatus::Denied);
        }
        Ok(Self {
            designated_requirement,
        })
    }

    pub(super) fn verify_current_process(&self) -> Result<(), StoreStatus> {
        let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
        let requirement = SecRequirement::from_str(&self.designated_requirement)
            .map_err(|_| StoreStatus::Denied)?;
        let code = SecCode::for_self(flags).map_err(|_| StoreStatus::Denied)?;
        code.check_validity(flags, &requirement)
            .map_err(|_| StoreStatus::Denied)
    }
}
