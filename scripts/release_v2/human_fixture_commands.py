"""Static command-position checks for inert human fixture text."""

import shlex


_SEPARATORS = frozenset((";", "&", "&&", "||", "|"))
_WRAPPERS = frozenset(("command", "doas", "env", "nohup", "sudo", "time"))
_SHELLS = frozenset(("bash", "sh", "zsh"))
_PACKAGE_COMMANDS = frozenset(("cargo", "npm", "pnpm", "yarn"))
_INFRA_COMMANDS = frozenset(("helm", "kubectl", "pulumi", "terraform"))
_CLOUD_COMMANDS = frozenset(("aws", "az", "cloudflare", "gcloud", "railway", "vercel"))
_DATABASE_COMMANDS = frozenset(("mongosh", "mysql", "psql", "redis-cli"))
_GIT_VALUE_OPTIONS = frozenset(("-C", "-c", "--config-env", "--git-dir", "--namespace", "--super-prefix", "--work-tree"))
_GIT_FLAGS = frozenset(("--bare", "--exec-path", "--glob-pathspecs", "--help", "--icase-pathspecs", "--literal-pathspecs", "--no-optional-locks", "--no-pager", "--no-replace-objects", "--noglob-pathspecs", "--paginate", "--version", "-p", "-P"))
_GH_VALUE_OPTIONS = frozenset(("--hostname", "--repo", "-R"))
_GH_FLAGS = frozenset(("--help", "--version"))
_KNOWN_COMMANDS = _WRAPPERS | _SHELLS | _PACKAGE_COMMANDS | _INFRA_COMMANDS | _CLOUD_COMMANDS | _DATABASE_COMMANDS | frozenset(("codesign", "cosign", "curl", "docker", "gh", "git", "gpg", "notarytool", "stapler", "wget", "xcrun"))


def contains_production_command(text: str) -> bool:
    """Return whether static shell-position tokens describe a prohibited action."""
    return _scan_text(text, 0)


def _scan_text(text: str, depth: int) -> bool:
    if depth > 8:
        return True
    return any(_line_has_command(line, depth) for line in text.splitlines())


def _line_has_command(line: str, depth: int) -> bool:
    tokens = _tokens(line)
    if tokens is None:
        return _starts_known(line)
    segments = _segments(tokens)
    if _has_substitution(line) and any(_command_like(segment, line) for segment in segments):
        return True
    for segment in segments:
        if _segment_has_command(segment, depth):
            return True
    return False


def _tokens(line: str) -> tuple[str, ...] | None:
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.commenters = ""
        lexer.whitespace_split = True
        return tuple(lexer)
    except ValueError:
        return None


def _segments(tokens: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    segments: list[tuple[str, ...]] = []
    current: list[str] = []
    for token in tokens:
        if token in _SEPARATORS:
            if current:
                segments.append(tuple(current))
                current = []
        else:
            current.append(token)
    if current:
        segments.append(tuple(current))
    return tuple(segments)


def _segment_has_command(tokens: tuple[str, ...], depth: int) -> bool:
    if tokens and tokens[0] == "$":
        tokens = tokens[1:]
    tokens = _skip_assignments(tokens)
    if not tokens:
        return False
    if _assignment_like(tokens[0]):
        return _segment_has_command(tokens[1:], depth)
    while True:
        command = _basename(tokens[0])
        arguments = tokens[1:]
        if command in {"sudo", "doas"}:
            return True
        if command == "env":
            tokens = _unwrap_env(arguments)
        elif command == "command":
            tokens = _unwrap_command(arguments)
        elif command == "nohup":
            tokens = _unwrap_nohup(arguments)
        elif command == "time":
            tokens = _unwrap_time(arguments)
        elif command in _SHELLS:
            return _shell_has_command(arguments, depth)
        else:
            return _prohibited(command, arguments)
        if tokens is None:
            return True


def _basename(token: str) -> str:
    return token.rstrip("/").rsplit("/", 1)[-1]


def _starts_known(line: str) -> bool:
    command = line.lstrip().removeprefix("$ ").split(None, 1)
    return bool(command) and _basename(command[0]) in _KNOWN_COMMANDS


def _has_substitution(line: str) -> bool:
    return "$(" in line or "`" in line


def _command_like(tokens: tuple[str, ...], line: str) -> bool:
    if tokens and tokens[0] == "$":
        tokens = tokens[1:]
    tokens = _skip_assignments(tokens)
    return bool(tokens) and (_basename(tokens[0]) in _KNOWN_COMMANDS or line.lstrip().removeprefix("$ ").startswith(("$(", "`")))


def _unwrap_env(arguments: tuple[str, ...]) -> tuple[str, ...] | None:
    index = 0
    options = True
    while index < len(arguments):
        argument = arguments[index]
        if options and argument == "--":
            index += 1
            options = False
        elif options and argument in {"-i", "--ignore-environment", "-0", "--null"}:
            index += 1
        elif options and argument in {"-u", "--unset", "--chdir"}:
            index += 2
        elif options and argument.startswith(("--chdir=", "--unset=")):
            index += 1
        elif options and argument.startswith("-"):
            return None
        elif _assignment(argument):
            index += 1
        else:
            break
    return arguments[index:] or None


def _unwrap_command(arguments: tuple[str, ...]) -> tuple[str, ...] | None:
    while arguments[:1] == ("-p",):
        arguments = arguments[1:]
    if arguments[:1] == ("--",):
        arguments = arguments[1:]
    elif arguments[:1] and arguments[0].startswith("-"):
        return None
    return arguments or None


def _unwrap_nohup(arguments: tuple[str, ...]) -> tuple[str, ...] | None:
    if arguments[:1] == ("--",):
        arguments = arguments[1:]
    elif arguments[:1] and arguments[0].startswith("-"):
        return None
    return arguments or None


def _unwrap_time(arguments: tuple[str, ...]) -> tuple[str, ...] | None:
    index = 0
    while index < len(arguments) and arguments[index].startswith("-"):
        argument = arguments[index]
        if argument in {"-p", "-v", "--verbose"} or argument.startswith(("--output=", "--format=")):
            index += 1
        elif argument in {"-o", "--output", "-f", "--format"}:
            index += 2
        elif argument == "--":
            index += 1
            break
        else:
            return None
    return arguments[index:] or None


def _assignment(token: str) -> bool:
    name, separator, _ = token.partition("=")
    return bool(separator and name and (name[0].isalpha() or name[0] == "_") and all(char.isascii() and (char.isalnum() or char == "_") for char in name))


def _assignment_like(token: str) -> bool:
    return "=" in token


def _skip_assignments(tokens: tuple[str, ...]) -> tuple[str, ...]:
    index = 0
    while index < len(tokens) and _assignment(tokens[index]):
        index += 1
    return tokens[index:]


def _shell_has_command(arguments: tuple[str, ...], depth: int) -> bool:
    if len(arguments) < 2 or arguments[0] != "-c":
        return True
    return _scan_text(arguments[1], depth + 1)


def _prohibited(command: str, arguments: tuple[str, ...]) -> bool:
    if command == "git":
        return _git_action(arguments)
    if command == "gh":
        return _gh_action(arguments)
    if command in _PACKAGE_COMMANDS:
        return _action(arguments, frozenset(("publish", "upload")))
    if command == "docker":
        return _action(arguments, frozenset(("push",)))
    if command == "cosign":
        return _action(arguments, frozenset(("attest", "sign", "sign-blob")))
    if command == "gpg":
        return _action(arguments, frozenset(("--clearsign", "--detach-sign", "--sign", "-b", "-s")))
    if command == "xcrun":
        return _action(arguments, frozenset(("notarytool", "stapler")))
    if command in {"codesign", "curl", "notarytool", "stapler", "wget"} | _CLOUD_COMMANDS | _DATABASE_COMMANDS:
        return True
    if command in _INFRA_COMMANDS:
        return _action(arguments, frozenset(("apply", "deploy", "destroy", "push", "upgrade"))) or not arguments
    return False


def _git_action(arguments: tuple[str, ...]) -> bool:
    action = _global_action(arguments, _GIT_VALUE_OPTIONS, _GIT_FLAGS)
    return action is None or action in {"push", "tag"}


def _gh_action(arguments: tuple[str, ...]) -> bool:
    action = _global_action(arguments, _GH_VALUE_OPTIONS, _GH_FLAGS)
    return action is None or action == "release"


def _global_action(arguments: tuple[str, ...], value_options: frozenset[str], flags: frozenset[str]) -> str | None:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            index += 1
            break
        if argument in value_options:
            index += 2
        elif argument in flags or any(argument.startswith(option + "=") for option in value_options):
            index += 1
        elif argument.startswith("-"):
            return None
        else:
            return argument
    return arguments[index] if index < len(arguments) else None


def _action(arguments: tuple[str, ...], actions: frozenset[str]) -> bool:
    return any(argument in actions for argument in arguments)
