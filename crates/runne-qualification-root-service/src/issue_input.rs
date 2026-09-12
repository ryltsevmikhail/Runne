use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_qualification_runner::BootstrapArmed;

use crate::issuer::UnsignedBootstrap;

pub fn from_armed(armed: &BootstrapArmed) -> UnsignedBootstrap {
    let binding = armed.binding();
    UnsignedBootstrap {
        schema_version: "runne/macos-xpc-dpk-run-bootstrap/v1",
        context_id: hex::encode(armed.context_id()),
        challenge: hex::encode(armed.challenge()),
        candidate_sha256: hex::encode(binding.candidate_sha256()),
        raw_v3_tuple_sha256: hex::encode(binding.raw_v3_tuple_sha256()),
        source_revision: hex::encode(binding.source_revision()),
        workflow_run_id: binding.workflow_run_id().into(),
        namespace_sha256: hex::encode(binding.namespace_sha256()),
        manifest_sha256: hex::encode(binding.manifest_sha256()),
        profile_sha256: hex::encode(binding.profile_sha256()),
        issued_at: armed.issued_at(),
        expires_at: armed.expires_at(),
        run_not_after: armed.run_not_after(),
        nonce: URL_SAFE_NO_PAD.encode(armed.nonce()),
    }
}
