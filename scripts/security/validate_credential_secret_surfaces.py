#!/usr/bin/env python3
"""Validate exact provider-credential secret ownership and absent surfaces."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from credential_secret_dispatch_rules import validate_provider_dispatch


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str


class Validator:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.findings: list[Finding] = []

    def read(self, path: str) -> str:
        target = self.root / path
        try:
            return target.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            self.fail("GUARD_INPUT", path, f"cannot read guarded file: {error}")
            return ""

    def fail(self, code: str, path: str, detail: str) -> None:
        self.findings.append(Finding(code, path, detail))

    def require(self, path: str, code: str, *anchors: str) -> str:
        source = self.read(path)
        missing = [anchor for anchor in anchors if anchor not in source]
        if missing:
            self.fail(code, path, f"missing invariant anchor: {missing[0]}")
        return source

    def require_count(self, path: str, code: str, anchor: str, count: int) -> str:
        source = self.read(path)
        if source.count(anchor) != count:
            self.fail(code, path, f"expected {count} occurrences of: {anchor}")
        return source

    def exact_fields(self, path: str, marker: str, expected: set[str], code: str) -> None:
        source = self.read(path)
        body = brace_body(source, marker)
        if body is None:
            self.fail(code, path, f"missing declaration: {marker}")
            return
        fields = set(re.findall(r"^\s*(?:readonly\s+|pub(?:\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:", body, re.M))
        if fields != expected:
            self.fail(code, path, f"fields changed: got {sorted(fields)}")

    def validate_surfaces(self) -> None:
        self.exact_fields(
            "apps/desktop/src/shared/api/platform/providers.ts",
            "export type ProviderCredentialProjection",
            {
                "providerId", "credentialState", "readiness", "lifecycleRevision",
                "readinessRevision", "observedAt", "verificationState",
                "verificationRevision", "pendingOperation", "cleanupPending",
                "lastDisposition",
            },
            "SURFACE_RENDERER_PROJECTION",
        )
        vue = self.read("apps/desktop/src/pages/providers/ui/ProvidersPage.vue")
        if re.search(r"<(?:input|textarea)\b", vue, re.I):
            self.fail("SURFACE_RENDERER_PROMPT", "apps/desktop/src/pages/providers/ui/ProvidersPage.vue", "renderer input element found")
        self.exact_fields(
            "apps/desktop/src-tauri/src/provider_credential_enrollment/command.rs",
            "pub struct CredentialIntentIpc",
            {"provider", "action", "expected_revision", "renderer_generation", "verification_kind"},
            "SURFACE_TAURI_INTENT",
        )
        app_core = self.read("crates/runne-app-core/src/lib_parts/providers.rs")
        for identifier in ("PairProviderCredentialRequest", "CredentialMaterial", "pair_provider_credential"):
            if identifier in app_core:
                self.fail("SURFACE_APP_CORE", "crates/runne-app-core/src/lib_parts/providers.rs", f"material ingress identifier: {identifier}")
        runtime_v1 = self.read("crates/runne-runtime-client/src/canonical/provider_credentials.rs")
        for identifier in ("PairProviderCredentialRequest", "pair_provider_credential", "CredentialMaterial"):
            if identifier in runtime_v1:
                self.fail("SURFACE_RUNTIME_CLIENT_V1", "crates/runne-runtime-client/src/canonical/provider_credentials.rs", f"material API identifier: {identifier}")
        http_path = "crates/runne-http/src/provider_credentials.rs"
        http = self.require(
            http_path,
            "SURFACE_PUBLIC_HTTP_V1",
            "async fn v1_unsupported(Extension(request_id): Extension<RequestId>) -> Response",
            "put(v1_unsupported).delete(v1_unsupported)",
        )
        if "Json<" in http or "requestBody" in http:
            self.fail("SURFACE_PUBLIC_HTTP_V1", http_path, "V1 handler accepts a body declaration")
        self.validate_v1_contracts()

    def validate_v1_contracts(self) -> None:
        schema_path = "contracts/gocode-ui-client-2/schemas/provider-credentials-v1.schema.json"
        openapi_path = "contracts/gocode-ui-client-2/openapi.json"
        try:
            schema = json.loads(self.read(schema_path))
            definitions = schema.get("$defs", {})
            if "pairRequest" in definitions:
                self.fail("SURFACE_PUBLIC_CONTRACT_V1", schema_path, "pairRequest material schema remains")
            openapi = json.loads(self.read(openapi_path))
            route = openapi["paths"]["/v1/providers/{provider}/credential"]
            if "requestBody" in route.get("put", {}):
                self.fail("SURFACE_PUBLIC_CONTRACT_V1", openapi_path, "PUT request body remains")
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            self.fail("SURFACE_PUBLIC_CONTRACT_V1", openapi_path, f"invalid guarded contract: {error}")

    def validate_secret_types(self) -> None:
        specs = (
            ("crates/runne-provider/src/credential/enrollment/service_protocol/types.rs", "CredentialMaterial", {"from_bytes", "from_zeroizing", "into_zeroizing", "consume"}),
            ("crates/runne-provider/src/credential/enrollment/service_protocol/types.rs", "CredentialMutationGrant", {"generate", "digest"}),
            ("crates/runne-platform-ports/src/provider_credential_prompt.rs", "SecureCredentialMaterial", {"new", "from_zeroizing", "into_pipe_bytes"}),
            ("crates/runne-platform-ports/src/provider_credential_prompt.rs", "CredentialPipeBytes", {"into_zeroizing"}),
            ("crates/runne-secure-store/src/provider_credential/policy.rs", "ProviderCredentialSource", {"new", "material", "revision", "into_material"}),
            ("crates/runne-secure-store/src/provider_credential/policy.rs", "ProviderCredentialMaterial", {"new", "from_zeroizing", "with_bytes", "into_zeroizing"}),
        )
        for path, name, allowed_public in specs:
            source = self.read(path)
            declaration = re.search(rf"(?P<prefix>(?:#\[[^\n]+\]\s*)*)pub struct {name}\b", source)
            if declaration is None:
                self.fail("SECRET_TYPE_MISSING", path, f"missing {name}")
                continue
            if re.search(r"\b(?:Clone|Debug|Serialize|Deserialize)\b", declaration.group("prefix")) or re.search(rf"impl\s+(?:[^\n]*::)?(?:Clone|Debug|Serialize|Deserialize)\s+for\s+{name}\b", source):
                self.fail("SECRET_TYPE_TRAITS", path, f"{name} gained a prohibited trait")
            body = brace_body(source, f"impl {name} {{")
            if body is None:
                self.fail("SECRET_TYPE_MISSING", path, f"missing impl {name}")
                continue
            public = set(re.findall(r"\bpub\s+fn\s+([A-Za-z_]\w*)", body))
            public.update(re.findall(r"\bpub\s+const\s+fn\s+([A-Za-z_]\w*)", body))
            unexpected = public - allowed_public
            borrowed_material = re.search(
                r"\bpub\s+(?:const\s+)?fn\s+[A-Za-z_]\w*[^;{]*"
                r"->\s*&(?:'[_A-Za-z]\w*\s+)?(?:\[u8\]|str)",
                body,
            )
            if borrowed_material or unexpected & {"as_bytes", "as_str", "bytes", "material", "expose", "borrow"}:
                self.fail("SECRET_PUBLIC_BORROW", path, f"{name} exposes {sorted(unexpected)}")
            constructors = {item for item in unexpected if item == "new" or item.startswith("from_") or item in {"unchecked", "from_raw"}}
            if constructors:
                self.fail("SECRET_UNBOUNDED_CONSTRUCTOR", path, f"{name} exposes unapproved constructors {sorted(constructors)}")
        frame_source = self.read("crates/runne-provider/src/credential/enrollment/service_protocol/frame.rs")
        for name in ("CredentialServiceRequestFrame", "CredentialServiceReplyFrame", "CredentialWriterBrokerHandoffFrame"):
            if re.search(rf"(?:derive\([^)]*(?:Clone|Debug|Serialize|Deserialize)[^)]*\)[\s\S]{{0,80}})?pub struct {name}", frame_source) and re.search(rf"#\[derive\([^]]*(?:Clone|Debug|Serialize|Deserialize)[^]]*\)\]\s*pub struct {name}", frame_source):
                self.fail("SECRET_TYPE_TRAITS", "crates/runne-provider/src/credential/enrollment/service_protocol/frame.rs", f"{name} gained a prohibited derive")

    def validate_task2(self) -> None:
        checks = (
            ("crates/runne-provider/src/credential/enrollment/service_protocol/codec.rs", "TASK2_WRITER_ZEROIZING_DECODE", "take_zeroizing_vec(bytes, &mut at)?", "Some(CredentialMaterial::from_wire(value)?)"),
            ("crates/runne-provider/src/credential/enrollment/service_protocol/codec/reply.rs", "TASK2_REPLY_ZEROIZING_DECODE", "CredentialMaterial::from_wire(take_zeroizing_vec(bytes, at)?)?"),
            ("crates/runne-credential-service/src/keychain/native.rs", "TASK2_KEYCHAIN_WRAP_FIRST", "let material = Zeroizing::new(material.bytes().to_vec());", "CredentialMaterial::from_zeroizing(material)"),
            ("crates/runne-credential-service/src/service_backend.rs", "TASK2_MEMORY_MOVE_OWNERSHIP", "material: material.into_zeroizing(),", "CredentialMaterial::from_zeroizing(item.material.clone())"),
        )
        for path, code, *anchors in checks:
            self.require(path, code, *anchors)
        self.require_count(
            "crates/runne-credential-service/src/service_backend.rs",
            "TASK2_MEMORY_MOVE_OWNERSHIP",
            "material: material.into_zeroizing(),",
            2,
        )

    def validate_task3(self) -> None:
        self.require(
            "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos.rs",
            "TASK3_PROMPT_CLEANUP_MODULE", "mod cleanup;", "mod routes;", "mod state;",
        )
        routes = self.require(
            "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/routes.rs",
            "TASK3_PROMPT_CLEANUP_ROUTE", "cleanup::finish_unregistered(prompt);",
            "terminal.cancel_pending(Err(SecureCredentialPromptError::Unavailable))",
            "fallback.finish_registered(id, Err(SecureCredentialPromptError::Unavailable));",
            "let _ = cleanup_receiver.recv();", "receiver\n                .recv()",
        )
        if routes.count("cleanup::finish(id);") != 2:
            self.fail("TASK3_PROMPT_CLEANUP_ROUTE", "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/routes.rs", "registered and late-setup terminal routes must clean up")
        self.require(
            "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos.rs",
            "TASK3_PROMPT_SYNCHRONIZED_TERMINAL", "native::schedule_main(move || {",
            "&terminal,", "native::schedule_main",
        )
        cleanup = self.require(
            "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/cleanup.rs",
            "TASK3_PROMPT_CLEANUP_ORDER", "field.clear_and_release();", "state::remove_cleaning(id)", "prompt.close_sheet();",
        )
        if cleanup.find("field.clear_and_release();") > cleanup.find("state::remove_cleaning(id)"):
            self.fail("TASK3_PROMPT_CLEANUP_ORDER", "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/cleanup.rs", "state removed before field clear")

    def validate_task4(self) -> None:
        self.require(
            "crates/runne-macos-xpc/src/client/native/exchange.rs",
            "TASK4_SINGLE_TERMINAL_CALL", "NativeCallState", "call.close_unknown(UnknownTerminal::Timeout);", "call.close_unknown(UnknownTerminal::Cancelled);", "call.close_unknown(terminal);",
        )
        self.require(
            "crates/runne-macos-xpc/src/client/native/call_state.rs",
            "TASK4_SINGLE_TERMINAL_CALL", "terminal.closed = true;", "terminal.request.take()", "invalidation_requested", "impl Drop for NativeCallState",
        )
        self.require(
            "crates/runne-macos-xpc/src/frame.rs",
            "TASK4_FRAME_BOUND", "bytes.len() > MAX_CREDENTIAL_SERVICE_FRAME_BYTES", "length > runne_platform_ports::credential_service::MAX_CREDENTIAL_SERVICE_FRAME_BYTES", "Zeroizing::new(vec![0_u8; length])",
        )
        self.require(
            "crates/runne-macos-xpc/src/client/native.rs",
            "TASK4_PRODUCTION_EXCHANGE", "native::request_data(request)", "native::copy_reply", "exchange::exchange(Arc::clone(&self.connection)",
        )

    def run(self) -> list[Finding]:
        self.validate_surfaces()
        self.validate_secret_types()
        self.validate_task2()
        self.validate_task3()
        self.validate_task4()
        validate_provider_dispatch(self, brace_body)
        return self.findings


def brace_body(source: str, marker: str) -> str | None:
    start = source.find(marker)
    if start < 0:
        return None
    opening = source.find("{", start)
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    findings = Validator(args.root.resolve()).run()
    if findings:
        for finding in findings:
            print(f"{finding.code}: {finding.path}: {finding.detail}")
        return 1
    print("credential secret surfaces: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
