"""Focused provider-dispatch rules for the credential lifetime validator."""

from __future__ import annotations

import re
from collections.abc import Callable


def validate_provider_dispatch(
    validator: object,
    brace_body: Callable[[str, str], str | None],
) -> None:
    validator.require(
        "crates/runne-secure-store/src/provider_credential/material.rs",
        "PROVIDER_DISPATCH_ZEROIZING_TRANSFER",
        "pub fn from_zeroizing(",
        "pub fn into_zeroizing(",
    )
    validator.require(
        "crates/runne-daemon/src/protected_activation/credential_service_gateway/materializer.rs",
        "PROVIDER_DISPATCH_ZEROIZING_TRANSFER",
        "ProviderCredentialMaterial::from_zeroizing(material.into_zeroizing())",
    )
    clients = (
        ("crates/runne-daemon-openai-effect/src/client.rs", "OpenAi"),
        ("crates/runne-daemon-deepseek-effect/src/client.rs", "DeepSeek"),
    )
    for path, provider in clients:
        source = validator.require(
            path,
            "PROVIDER_DISPATCH_ZEROIZING_TRANSFER",
            ".map(|material| material.into_zeroizing().1)",
        )
        body = brace_body(
            source,
            f"impl {provider}CredentialMaterializer for NativeCredential {{",
        )
        if body is None or ".to_vec()" in body or ".with_bytes(" in body:
            validator.fail(
                "PROVIDER_DISPATCH_ZEROIZING_TRANSFER",
                path,
                "native materializer gained an ordinary material copy",
            )

    for path in (
        "crates/runne-daemon-openai-effect/src/bounds.rs",
        "crates/runne-daemon-deepseek-effect/src/bounds.rs",
    ):
        source = validator.require(
            path,
            "PROVIDER_AUTHORIZATION_OWNER",
            "struct AuthorizationOwner",
            "wire: Zeroizing<Vec<u8>>",
            "header.set_sensitive(true);",
            "impl Drop for AuthorizationOwner",
        )
        declaration = re.search(
            r"(?P<prefix>(?:#\[[^\n]+\]\s*)*)struct AuthorizationOwner\b",
            source,
        )
        prohibited = r"Clone|Debug|Serialize|Deserialize"
        gained_trait = declaration is None or re.search(
            rf"\b(?:{prohibited})\b", declaration.group("prefix")
        ) or re.search(rf"impl\s+(?:[^\n]*::)?(?:{prohibited})\s+for\s+AuthorizationOwner\b", source)
        constructor = brace_body(source, "impl AuthorizationOwner {")
        ordinary_copy = constructor is None or re.search(
            r"credential[^;\n]*(?:\.to_vec\(\)|\.to_owned\(\)|\.clone\(\))",
            constructor,
        )
        if gained_trait or ordinary_copy:
            validator.fail(
                "PROVIDER_AUTHORIZATION_OWNER",
                path,
                "authorization owner gained a prohibited trait or ordinary credential copy",
            )
