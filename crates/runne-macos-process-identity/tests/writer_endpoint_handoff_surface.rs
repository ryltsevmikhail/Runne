#[cfg(target_os = "macos")]
#[test]
fn handoff_surface_has_only_the_fixed_stdin_constructor() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/writer_endpoint_handoff.rs")).unwrap();
    let facade = std::fs::read_to_string(root.join("src/lib.rs")).unwrap();

    assert!(source.contains("pub struct MacOsUntrustedWriterEndpointHandoffV1"));
    assert!(source.contains("pub fn receive_from_stdin() -> std::io::Result<Self>"));
    assert!(source.contains("#[doc(hidden)]"));
    assert!(
        facade.contains("pub use writer_endpoint_handoff::MacOsUntrustedWriterEndpointHandoffV1;")
    );

    for forbidden in [
        "derive(",
        "impl Clone",
        "impl Copy",
        "impl Debug",
        "impl Default",
        "impl serde::",
        "impl AsFd",
        "impl AsRawFd",
        "impl IntoRawFd",
        "pub fn from_parts",
        "pub fn channel_binding",
        "pub fn publication_public_key",
        "pub fn handoff_digest",
        "pub fn frame",
        "pub fn control",
        "pub fn into_authority",
        "pub fn mint",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}
