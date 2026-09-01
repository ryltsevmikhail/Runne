use serde::{Deserialize, Serialize};

/// Signed expectation data; never an observed identity or identity proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacOsCodeIdentityExpectationV1 {
    identifier: String,
    team_identifier: String,
    cdhash: String,
}

impl MacOsCodeIdentityExpectationV1 {
    pub(super) fn new(
        identifier: impl Into<String>,
        team_identifier: impl Into<String>,
        cdhash: impl Into<String>,
    ) -> Option<Self> {
        let identity = Self {
            identifier: identifier.into(),
            team_identifier: team_identifier.into(),
            cdhash: cdhash.into(),
        };
        identity.valid().then_some(identity)
    }

    pub const fn identifier(&self) -> &str {
        self.identifier.as_str()
    }
    pub const fn team_identifier(&self) -> &str {
        self.team_identifier.as_str()
    }
    pub const fn cdhash(&self) -> &str {
        self.cdhash.as_str()
    }

    pub(super) fn valid(&self) -> bool {
        !self.identifier.is_empty()
            && self
                .identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            && self.team_identifier.len() == 10
            && self
                .team_identifier
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            && self.cdhash.len() == 40
            && self
                .cdhash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }

    pub(super) fn digest_fields(&self) -> [&str; 3] {
        [&self.identifier, &self.team_identifier, &self.cdhash]
    }
}
