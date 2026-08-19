//! Closed grammar for the independently configured macOS designated requirement.

const IDENTIFIER: &str = "com.runne.project-owner.authority";
const PREFIX: &str = "identifier \"com.runne.project-owner.authority\" and anchor apple generic and certificate leaf[subject.OU] = \"";
const SUFFIX: &str = "\"";
const TEAM_ID_BYTES: usize = 10;
const MAX_REQUIREMENT_BYTES: usize = PREFIX.len() + TEAM_ID_BYTES + SUFFIX.len();

/// Accept precisely one non-ambiguous designated-requirement grammar.
///
/// The team identifier is intentionally configurable, but all other syntax is fixed. The
/// subsequent `SecRequirement` validation binds that parsed requirement to the current process.
pub(super) fn valid_designated_requirement(requirement: &str) -> bool {
    if requirement.len() != MAX_REQUIREMENT_BYTES
        || !requirement.is_ascii()
        || requirement.bytes().any(|byte| byte.is_ascii_control())
        || requirement.contains(" or ")
        || requirement.contains("=>")
        || requirement.contains('*')
    {
        return false;
    }
    let Some(team_id) = requirement
        .strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
    else {
        return false;
    };
    team_id.len() == TEAM_ID_BYTES
        && team_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && requirement.contains(IDENTIFIER)
}

#[cfg(test)]
mod tests {
    use super::valid_designated_requirement;

    const VALID: &str = "identifier \"com.runne.project-owner.authority\" and anchor apple generic and certificate leaf[subject.OU] = \"AB12CD34EF\"";

    #[test]
    fn requires_one_exact_quoted_identifier_and_team_clause() {
        assert!(valid_designated_requirement(VALID));
        for invalid in [
            "identifier \"com.runne.other\" and anchor apple generic and certificate leaf[subject.OU] = \"AB12CD34EF\"",
            "identifier \"com.runne.project-owner.authority\" and anchor apple generic",
            "identifier \"com.runne.project-owner.authority\" or certificate leaf[subject.OU] = \"AB12CD34EF\"",
            "identifier \"com.runne.project-owner.authority\" and anchor apple generic and certificate leaf[subject.OU] = \"AB12CD34EF\" => true",
            "identifier \"com.runne.project-owner.*\" and anchor apple generic and certificate leaf[subject.OU] = \"AB12CD34EF\"",
            "identifier \"com.runne.project-owner.authority\" and anchor apple generic and certificate leaf[subject.OU] = \"AB12CD34EF\"\n",
            "identifier \"com.runne.project-owner.authority\" and anchor apple generic and certificate leaf[subject.OU] = \"ab12cd34ef\"",
        ] {
            assert!(
                !valid_designated_requirement(invalid),
                "accepted {invalid:?}"
            );
        }
    }
}
