use std::fmt;

use crate::CredentialServiceXpcError;

const MAX_REQUIREMENT_BYTES: usize = 4 * 1024;

/// One of the three physically separate credential-service endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServiceEndpointRole {
    Desktop,
    Runtime,
    Writer,
}

impl CredentialServiceEndpointRole {
    #[must_use]
    pub const fn endpoint_name(self) -> &'static str {
        match self {
            Self::Desktop => "com.runne.credential-service.desktop.v1",
            Self::Runtime => "com.runne.credential-service.runtime.v1",
            Self::Writer => "com.runne.credential-service.writer.v1",
        }
    }
}

/// Validated designated requirement retained only inside the native adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialServicePeerRequirement(String);

impl CredentialServicePeerRequirement {
    /// Validates the one canonical exact identity requirement grammar.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection for malformed or oversized text.
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialServiceXpcError> {
        let value = value.into();
        if value.len() > MAX_REQUIREMENT_BYTES || !valid_canonical_requirement(&value) {
            return Err(CredentialServiceXpcError::Rejected);
        }
        Ok(Self(value))
    }

    /// Retains one local codesign-designated requirement for package-shaped
    /// real-process tests that cannot possess a Developer ID certificate.
    ///
    /// This constructor is absent from production builds. It does not accept a
    /// caller-selected identifier, multiline value, NUL, or an unbounded rule.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection unless the requirement starts with the exact
    /// locally signed executable identifier and remains one bounded line.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn from_local_designated_requirement(
        expected_identifier: &str,
        value: impl Into<String>,
    ) -> Result<Self, CredentialServiceXpcError> {
        let value = value.into();
        let prefix = format!("identifier \"{expected_identifier}\" and ");
        if !valid_local_identifier(expected_identifier)
            || value.len() > MAX_REQUIREMENT_BYTES
            || !value.starts_with(&prefix)
            || value
                .bytes()
                .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
        {
            return Err(CredentialServiceXpcError::Rejected);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "test-support")]
fn valid_local_identifier(value: &str) -> bool {
    value
        .strip_prefix("dev.runne.slice-e.")
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'-'))
        })
}

fn valid_canonical_requirement(value: &str) -> bool {
    const IDENTIFIER_PREFIX: &str = "identifier \"";
    const TEAM_SEPARATOR: &str =
        "\" and anchor apple generic and certificate leaf[subject.OU] = \"";
    const CDHASH_SEPARATOR: &str = "\" and cdhash H\"";
    let Some(after_identifier) = value.strip_prefix(IDENTIFIER_PREFIX) else {
        return false;
    };
    let Some((identifier, after_team_separator)) = after_identifier.split_once(TEAM_SEPARATOR)
    else {
        return false;
    };
    let Some((team, hash_and_quote)) = after_team_separator.split_once(CDHASH_SEPARATOR) else {
        return false;
    };
    let Some(hash) = hash_and_quote.strip_suffix('"') else {
        return false;
    };
    !identifier.is_empty()
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && hash.len() == 40
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

impl fmt::Debug for CredentialServicePeerRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialServicePeerRequirement(<redacted>)")
    }
}

/// Exact endpoint plus both directions of code-signing admission.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialServiceEndpointConfiguration {
    role: CredentialServiceEndpointRole,
    endpoint_name: &'static str,
    service_requirement: CredentialServicePeerRequirement,
    client_requirement: CredentialServicePeerRequirement,
}

impl CredentialServiceEndpointConfiguration {
    /// Creates one role-bound endpoint configuration.
    ///
    /// # Errors
    ///
    /// Rejects endpoint skew or equal client/service requirements.
    pub fn new(
        role: CredentialServiceEndpointRole,
        endpoint_name: &str,
        service_requirement: CredentialServicePeerRequirement,
        client_requirement: CredentialServicePeerRequirement,
    ) -> Result<Self, CredentialServiceXpcError> {
        if endpoint_name != role.endpoint_name() || service_requirement == client_requirement {
            return Err(CredentialServiceXpcError::Rejected);
        }
        Ok(Self {
            role,
            endpoint_name: role.endpoint_name(),
            service_requirement,
            client_requirement,
        })
    }

    #[must_use]
    pub const fn role(&self) -> CredentialServiceEndpointRole {
        self.role
    }
    #[must_use]
    pub const fn endpoint_name(&self) -> &'static str {
        self.endpoint_name
    }
    pub(crate) const fn service_requirement(&self) -> &CredentialServicePeerRequirement {
        &self.service_requirement
    }
    pub(crate) const fn client_requirement(&self) -> &CredentialServicePeerRequirement {
        &self.client_requirement
    }
}

impl fmt::Debug for CredentialServiceEndpointConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialServiceEndpointConfiguration")
            .field("role", &self.role)
            .field("endpoint_name", &self.endpoint_name)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct ConnectionPreparation {
    requirement: Option<CredentialServicePeerRequirement>,
    resumed: bool,
}

#[cfg(test)]
impl ConnectionPreparation {
    pub(crate) const fn new() -> Self {
        Self {
            requirement: None,
            resumed: false,
        }
    }

    pub(crate) fn install_requirement(
        &mut self,
        requirement: CredentialServicePeerRequirement,
    ) -> Result<(), CredentialServiceXpcError> {
        if self.resumed || self.requirement.is_some() {
            return Err(CredentialServiceXpcError::Rejected);
        }
        self.requirement = Some(requirement);
        Ok(())
    }

    pub(crate) fn resume(&mut self) -> Result<(), CredentialServiceXpcError> {
        if self.resumed || self.requirement.is_none() {
            return Err(CredentialServiceXpcError::Rejected);
        }
        self.resumed = true;
        Ok(())
    }
}

#[cfg(all(test, feature = "test-support"))]
mod local_tests {
    use super::*;

    #[test]
    fn local_designated_requirement_is_exact_bounded_and_feature_gated() {
        let identifier = "dev.runne.slice-e.credential-service";
        let local = format!("identifier \"{identifier}\" and anchor rootCert");
        assert!(CredentialServicePeerRequirement::new(&local).is_err());
        assert!(
            CredentialServicePeerRequirement::from_local_designated_requirement(identifier, &local)
                .is_ok()
        );
        for rejected in [
            CredentialServicePeerRequirement::from_local_designated_requirement(
                "com.runne.credential-service",
                &local,
            ),
            CredentialServicePeerRequirement::from_local_designated_requirement(
                identifier,
                local.replace(identifier, "dev.runne.slice-e.writer"),
            ),
            CredentialServicePeerRequirement::from_local_designated_requirement(
                identifier,
                format!("{local}\n or true"),
            ),
        ] {
            assert_eq!(rejected, Err(CredentialServiceXpcError::Rejected));
        }
    }
}
