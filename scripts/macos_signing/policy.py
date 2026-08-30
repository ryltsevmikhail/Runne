from .models import FailureCode, SigningFailure, SigningProfile


ALLOWED_PROGRAMS = {
    "/usr/bin/codesign",
    "/usr/bin/ditto",
    "/usr/bin/hdiutil",
    "/usr/sbin/spctl",
    "/usr/bin/xcrun",
}
MAX_ARGV_ITEMS = 32
MAX_ARGV_ITEM_BYTES = 1024
MAX_CAPTURED_OUTPUT_BYTES = 4096

_RAW_CREDENTIAL_ARGUMENTS = {
    "--password",
    "--key",
    "--key-id",
    "--issuer",
    "--sync",
    "--keychain",
    "--apple-id",
    "--team-id",
    "--token",
    "--api-key",
    "--credential",
}
_SHELL_METACHARACTER_FRAGMENTS = (";", "&&", "||", "|", "`", "$(", ">", "<", "\n", "\r")
_TOOL_STATUS_CODES = {code.value: code for code in FailureCode}


def parse_profile(value: str) -> SigningProfile | SigningFailure:
    try:
        return SigningProfile(value)
    except ValueError:
        return SigningFailure(FailureCode.UNKNOWN_PROFILE, "profile", "")


def map_tool_status(value: str) -> FailureCode | None:
    return _TOOL_STATUS_CODES.get(value, FailureCode.UNKNOWN_STATUS)


def contains_raw_credential_argument(argv: tuple[str, ...]) -> bool:
    return any(item in _RAW_CREDENTIAL_ARGUMENTS for item in argv)


def program_is_allowed(program: str) -> bool:
    return program.startswith("/") and program in ALLOWED_PROGRAMS


def command_arguments_are_safe(argv: tuple[str, ...]) -> bool:
    if len(argv) > MAX_ARGV_ITEMS or contains_raw_credential_argument(argv):
        return False
    return all(_argument_is_safe(item) for item in argv)


def _argument_is_safe(value: str) -> bool:
    return (
        len(value.encode("utf-8")) <= MAX_ARGV_ITEM_BYTES
        and "\0" not in value
        and value != "--deep"
        and not any(fragment in value for fragment in _SHELL_METACHARACTER_FRAGMENTS)
    )
