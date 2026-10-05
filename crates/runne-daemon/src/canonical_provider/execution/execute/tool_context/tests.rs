use super::validate_arguments;
use base64::Engine as _;

#[test]
fn read_context_accepts_only_canonical_flat_path_arguments() {
    assert_eq!(
        validate_arguments(br#"{"path":"notes.txt"}"#, "workspace.file.read").unwrap(),
        (r#"{"path":"notes.txt"}"#.to_owned(), None)
    );
    assert!(validate_arguments(br#"{"path":"../secret"}"#, "workspace.file.read").is_err());
    assert!(
        validate_arguments(
            br#"{"path":"notes.txt","extra":true}"#,
            "workspace.file.read"
        )
        .is_err()
    );
}

#[test]
fn create_context_decodes_exact_content_without_parsing_file_bytes_as_json() {
    let content = b"ordinary workspace bytes, not tool arguments";
    let encoded = base64::engine::general_purpose::STANDARD.encode(content);
    let arguments = serde_json::to_vec(&serde_json::json!({
        "path": "created.txt",
        "content_base64": encoded,
    }))
    .unwrap();
    let (canonical, decoded) = validate_arguments(&arguments, "workspace.file.create_new").unwrap();
    assert_eq!(canonical.as_bytes(), arguments.as_slice());
    assert_eq!(decoded.as_deref(), Some(content.as_slice()));
    assert!(
        validate_arguments(
            br#"{"path":"created.txt","content_base64":"%%%"}"#,
            "workspace.file.create_new"
        )
        .is_err()
    );
}
