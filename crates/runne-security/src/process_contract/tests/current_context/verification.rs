use super::super::super::ProcessContractError;
use super::super::support::{binding, cwd, executable, intent};
use super::assert_context_error;

macro_rules! verification_mismatch {
    ($name:ident, $expected:expr, $changed:expr) => {
        #[test]
        fn $name() {
            assert_context_error($changed, $expected);
        }
    };
}

verification_mismatch!(
    executable_held_token_substitution_is_denied,
    ProcessContractError::ExecutableVerificationFailed,
    intent(
        binding(1),
        10,
        executable(9, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
verification_mismatch!(
    executable_canonical_identity_substitution_is_denied,
    ProcessContractError::ExecutableVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 9, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
verification_mismatch!(
    executable_content_substitution_is_denied,
    ProcessContractError::ExecutableVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 9, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
verification_mismatch!(
    executable_filesystem_substitution_is_denied,
    ProcessContractError::ExecutableVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 9, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
verification_mismatch!(
    executable_version_substitution_is_denied,
    ProcessContractError::ExecutableVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 4, 2),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
verification_mismatch!(
    executable_policy_substitution_is_denied,
    ProcessContractError::ExecutableVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 4, 1),
        13,
        cwd(5, 6, 7, 1),
        12
    )
);
verification_mismatch!(
    cwd_held_token_substitution_is_denied,
    ProcessContractError::CwdVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(9, 6, 7, 1),
        12
    )
);
verification_mismatch!(
    cwd_canonical_identity_substitution_is_denied,
    ProcessContractError::CwdVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 9, 7, 1),
        12
    )
);
verification_mismatch!(
    cwd_filesystem_substitution_is_denied,
    ProcessContractError::CwdVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 9, 1),
        12
    )
);
verification_mismatch!(
    cwd_version_substitution_is_denied,
    ProcessContractError::CwdVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 2),
        12
    )
);
verification_mismatch!(
    cwd_allowed_root_substitution_is_denied,
    ProcessContractError::CwdVerificationFailed,
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        13
    )
);
