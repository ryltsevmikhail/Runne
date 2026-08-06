use super::source_manifest::source_violations;

#[test]
fn scanner_detects_grouped_alias_imports_and_concat_shell_container_literals() {
    let code = [
        "std::process",
        "std::fs",
        "std::env",
        "std::net",
        "tokio::process",
        "tokio::fs",
        "tokio::net",
    ];
    let sources = [
        (
            "std-process",
            "use std::{process::Command as C}; C::new(\"safe\");",
        ),
        ("std-fs", "use std::{fs as f};"),
        ("std-env", "use std::{env as e};"),
        ("std-net", "use std::{net as n};"),
        ("tokio-process", "use tokio::{process::Command as C};"),
        ("tokio-fs", "use tokio::{fs as f};"),
        ("tokio-net", "use tokio::{net as n};"),
        ("concat-shell", "let route = concat!(\"s\", \"h -c\");"),
        ("concat-container", "let route = concat!(\"doc\", \"ker\");"),
    ];
    let violations = source_violations(
        &sources,
        &code.into_iter().map(str::to_owned).collect::<Vec<_>>(),
        &["sh -c".to_owned(), "docker".to_owned()],
    );

    for expected in [
        "std-process: std::process",
        "std-fs: std::fs",
        "std-env: std::env",
        "std-net: std::net",
        "tokio-process: tokio::process",
        "tokio-fs: tokio::fs",
        "tokio-net: tokio::net",
        "concat-shell: literal sh -c",
        "concat-container: literal docker",
    ] {
        assert!(
            violations.contains(&expected.to_owned()),
            "missing {expected}"
        );
    }
}
