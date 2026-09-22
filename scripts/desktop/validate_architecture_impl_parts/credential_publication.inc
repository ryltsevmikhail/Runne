"""Keep daemon credential publication signing out of general provider surfaces."""

CREDENTIAL_PUBLICATION_SIGNER = re.compile(r"\bCredentialSecretPublicationSigner\b")
CREDENTIAL_PUBLICATION_PROVIDER_SOURCES = {
    Path("crates/runne-provider/src/lib.rs"),
    Path("crates/runne-provider/src/contract_doctests.rs"),
    Path("crates/runne-provider/src/credential/enrollment.rs"),
    Path("crates/runne-provider/src/credential/enrollment/protocol.rs"),
    Path("crates/runne-provider/src/credential/enrollment/protocol/secret.rs"),
    Path("crates/runne-provider/src/credential/enrollment/protocol/secret/publication.rs"),
    Path("crates/runne-provider/src/credential/enrollment/protocol/secret/tests/signer.rs"),
}
CREDENTIAL_PUBLICATION_DAEMON_ROOT = Path("crates/runne-daemon")


def find_credential_publication_signer_violations(root: Path) -> list[str]:
    """Signer references belong only to the daemon and narrow provider adapter."""
    violations = []
    for path in sorted((root / "crates").rglob("*.rs")):
        relative = path.relative_to(root)
        if relative in CREDENTIAL_PUBLICATION_PROVIDER_SOURCES:
            continue
        if relative.is_relative_to(CREDENTIAL_PUBLICATION_DAEMON_ROOT):
            continue
        if CREDENTIAL_PUBLICATION_SIGNER.search(path.read_text(encoding="utf-8")):
            violations.append(
                f"{relative.as_posix()} references the daemon-only credential publication signer"
            )
    return violations
