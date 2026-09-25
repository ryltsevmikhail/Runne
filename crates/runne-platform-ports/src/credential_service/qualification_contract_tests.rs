use std::path::Path;

use sha2::{Digest, Sha256};

fn workspace_source(relative: &str) -> String {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(workspace.join(relative)).unwrap()
}

fn workspace_bytes(relative: &str) -> Vec<u8> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read(workspace.join(relative)).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn trait_body<'a>(source: &'a str, marker: &str) -> &'a str {
    let source = source
        .split_once(marker)
        .expect("contract marker must exist")
        .1;
    let start = source.find('{').expect("contract body must open");
    let end = source[start..].find('}').expect("contract body must close");
    &source[start..=start + end]
}

#[test]
fn qualification_guard_does_not_allow_all_of_client_rs() {
    let source = include_str!("qualification.rs");
    assert!(
        !source.contains("ALLOWED_FILES"),
        "a production invocation in client.rs must not inherit a file-wide allowlist"
    );
}

#[test]
fn qualification_client_is_fail_closed_before_exchange() {
    let source = workspace_source("crates/runne-macos-xpc/src/client.rs");
    let implementation = trait_body(
        &source,
        "impl CredentialServiceQualificationPort for CredentialServiceRuntimeXpcClient",
    );
    assert!(implementation.contains("let _ = (request, context);"));
    assert!(implementation.contains("Err(CredentialServicePortError::Unsupported)"));
    assert!(!implementation.contains("exchange("));
    assert!(!implementation.contains("exchange_method!"));
}

#[test]
fn ordinary_runtime_port_remains_the_three_method_contract() {
    let source = workspace_source("crates/runne-platform-ports/src/credential_service/runtime.rs");
    let contract = trait_body(&source, "pub trait CredentialServiceRuntimePort");
    for method in ["arm_mutation", "read_metadata", "read_material"] {
        assert_eq!(contract.matches(&format!("fn {method}(")).count(), 1);
    }
    assert_eq!(contract.matches("fn ").count(), 3);
    assert!(!contract.contains("Qualification"));
}

#[test]
fn endpoint_roles_clients_frames_and_ceiling_remain_the_ordinary_triplet() {
    let peer = workspace_source("crates/runne-macos-xpc/src/peer_requirement.rs");
    let roles = trait_body(&peer, "pub enum CredentialServiceEndpointRole");
    assert_eq!(
        roles
            .lines()
            .filter_map(|line| line.trim().strip_suffix(','))
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>(),
        ["Desktop", "Runtime", "Writer"]
    );
    let client = workspace_source("crates/runne-macos-xpc/src/client.rs");
    assert_eq!(
        client
            .lines()
            .filter(|line| line.trim_start().starts_with("role_client!("))
            .map(str::trim)
            .collect::<Vec<_>>(),
        [
            "role_client!(CredentialServiceDesktopXpcClient, Desktop);",
            "role_client!(CredentialServiceRuntimeXpcClient, Runtime);",
            "role_client!(CredentialServiceWriterXpcClient, Writer);",
        ]
    );
    let frame = workspace_source("crates/runne-macos-xpc/src/frame.rs");
    assert_eq!(frame.matches("native_frame!(").count(), 2);
    assert_eq!(
        frame
            .matches("runne_credential_service_xpc_protocol_v1")
            .count(),
        2
    );
    assert!(!frame.contains("Qualification"));
    let port = include_str!("../credential_service.rs");
    assert!(port.contains("MAX_CREDENTIAL_SERVICE_FRAME_BYTES: usize = 16 * 1024"));
}

#[test]
fn ordinary_runtime_endpoint_frame_wire_and_ceiling_sources_are_golden() {
    let golden = [
        (
            "crates/runne-platform-ports/src/credential_service/runtime.rs",
            "e15842d5e30637dc36293b29920fb2c63166a309318832f112e36fe56fa0d95c",
        ),
        (
            "crates/runne-platform-ports/src/credential_service.rs",
            "977289c2f0e94792f0dd4f59853437401192173599079f5516cf23daf0c13c5d",
        ),
        (
            "crates/runne-macos-xpc/src/peer_requirement.rs",
            "8c93f0f473b664ade7b543ef9e7d280ad04a96774c1f99dc2eab87a53a3a0721",
        ),
        (
            "crates/runne-macos-xpc/src/frame.rs",
            "88fc4ad0df24ea95c3a8f77652308968fee2de4279689a91ad5791a8f5da2d96",
        ),
        (
            "crates/runne-macos-xpc/src/native_protocol.m",
            "f3a81381bac862c3afb143c17034de6cff0a5f59821401b39a2b7f4c5527d674",
        ),
        (
            "crates/runne-macos-xpc/build.rs",
            "fd7b11c5597b37a4095d42451e25f1e787b0a065f5f5e647faf5f5532d2df9fa",
        ),
    ];
    for (path, expected) in golden {
        assert_eq!(
            sha256_hex(&workspace_bytes(path)),
            expected,
            "golden drift: {path}"
        );
    }
}

#[test]
fn golden_surface_guard_rejects_protocol_frame_and_ceiling_additions() {
    let frame = workspace_bytes("crates/runne-macos-xpc/src/frame.rs");
    let mut altered_frame = frame.clone();
    altered_frame.extend_from_slice(
        b"\nunsafe extern \"C\" { fn runne_credential_service_xpc_protocol_v2(); }\n",
    );
    altered_frame.extend_from_slice(b"native_frame!(NativeQualificationFrame);\n");
    assert_ne!(sha256_hex(&altered_frame), sha256_hex(&frame));

    let ceiling = workspace_bytes("crates/runne-platform-ports/src/credential_service.rs");
    let mut altered_ceiling = ceiling.clone();
    altered_ceiling.extend_from_slice(
        b"\nconst ALTERNATE_CREDENTIAL_SERVICE_FRAME_BYTES: usize = 64 * 1024;\n",
    );
    assert_ne!(sha256_hex(&altered_ceiling), sha256_hex(&ceiling));
}
