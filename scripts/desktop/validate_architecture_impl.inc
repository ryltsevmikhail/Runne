"""Load architecture validation phases in one shared execution context."""
from pathlib import Path


parts = Path(__file__).with_name("validate_architecture_impl_parts")
for name in (
    "checks.inc",
    "renderer_channel_checks.inc",
    "credential_service_core_dependencies.inc",
    "native_qualification.inc",
    "native_process_identity.inc",
    "macos_process_identity_crate_dependencies.inc",
    "macos_xpc_source_scan.inc",
    "macos_xpc_adapter.inc",
    "credential_keychain_boundary.inc",
    "credential_publication.inc",
    "entrypoint.inc",
):
    exec((parts / name).read_text(encoding="utf-8"))
