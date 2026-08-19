//! Closed, testable Keychain query policy for project-owner authority records.

use crate::StoreStatus;

/// Fixed Keychain service; no legacy service is accepted.
pub const PROJECT_OWNER_KEYCHAIN_SERVICE: &str = "runne.project-owner.authority/1";
/// Dedicated configured access group for the independently signed owner tool.
pub const PROJECT_OWNER_KEYCHAIN_ACCESS_GROUP: &str = "com.runne.project-owner.authority";
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;

/// Only the three public protocol accounts, plus the private recovery journal, may exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectOwnerKeychainAccount {
    /// Active signing seed.
    Active,
    /// Pending, non-signing seed.
    Pending,
    /// Local anti-rollback floor.
    AnchorFloor,
    /// Private crash-recovery journal record.
    Recovery,
}

impl ProjectOwnerKeychainAccount {
    /// Return the fixed account selector.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::AnchorFloor => "anchor-floor",
            Self::Recovery => "recovery",
        }
    }
}

/// Complete immutable query contract for exactly one authority Keychain item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectOwnerKeychainQuery {
    account: ProjectOwnerKeychainAccount,
}

impl ProjectOwnerKeychainQuery {
    /// Construct a query for one closed account selector.
    ///
    /// # Errors
    ///
    /// This function is total for the closed account enum; errors are reserved for parity with
    /// string-based construction.
    pub const fn new(account: ProjectOwnerKeychainAccount) -> Result<Self, StoreStatus> {
        Ok(Self { account })
    }

    /// Parse only a closed account selector.
    ///
    /// # Errors
    ///
    /// Returns [`StoreStatus::Denied`] for every unknown or legacy account name.
    pub fn from_account(account: &str) -> Result<Self, StoreStatus> {
        let account = match account {
            "active" => ProjectOwnerKeychainAccount::Active,
            "pending" => ProjectOwnerKeychainAccount::Pending,
            "anchor-floor" => ProjectOwnerKeychainAccount::AnchorFloor,
            "recovery" => ProjectOwnerKeychainAccount::Recovery,
            _ => return Err(StoreStatus::Denied),
        };
        Self::new(account)
    }

    /// Return the fixed service selector.
    #[must_use]
    pub const fn service(self) -> &'static str {
        PROJECT_OWNER_KEYCHAIN_SERVICE
    }

    /// Return the exact account selector.
    #[must_use]
    pub const fn account(self) -> &'static str {
        self.account.as_str()
    }

    /// Return the dedicated access-group selector.
    #[must_use]
    pub const fn access_group(self) -> &'static str {
        PROJECT_OWNER_KEYCHAIN_ACCESS_GROUP
    }

    /// Data Protection Keychain must be selected for every operation.
    #[must_use]
    pub const fn requires_data_protection(self) -> bool {
        true
    }

    /// Items must never leave this physical device.
    #[must_use]
    pub const fn requires_this_device_only(self) -> bool {
        true
    }

    /// Any sensitive item access requires user presence.
    #[must_use]
    pub const fn requires_user_presence(self) -> bool {
        true
    }

    /// iCloud synchronization is prohibited for every account.
    #[must_use]
    pub const fn is_synchronizable(self) -> bool {
        false
    }
}

/// Map all native Keychain failures to closed, public non-secret operation statuses.
#[must_use]
pub const fn map_project_owner_keychain_status(status: i32) -> StoreStatus {
    match status {
        ERR_SEC_INTERACTION_NOT_ALLOWED => StoreStatus::UiUnavailable,
        _ => StoreStatus::Denied,
    }
}
