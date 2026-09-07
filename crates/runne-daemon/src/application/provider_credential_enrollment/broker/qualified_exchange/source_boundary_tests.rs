use std::{fs, path::PathBuf};

fn source(relative: &str) -> String {
    fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)).unwrap()
}

fn rust_sources(directory: &std::path::Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && path
                .file_stem()
                .is_none_or(|stem| !stem.to_string_lossy().ends_with("_tests"))
        {
            output.push(path);
        }
    }
}

fn sites_with(root: &std::path::Path, sources: &[PathBuf], needle: &str) -> Vec<PathBuf> {
    let mut sites = sources
        .iter()
        .filter(|path| fs::read_to_string(path).unwrap().contains(needle))
        .map(|path| path.strip_prefix(root).unwrap().to_owned())
        .collect::<Vec<_>>();
    sites.sort();
    sites
}

fn occurrences(sources: &[PathBuf], needle: &str) -> usize {
    sources
        .iter()
        .map(|path| fs::read_to_string(path).unwrap().matches(needle).count())
        .sum()
}

#[test]
fn qualified_signing_requires_the_single_fenced_transmission() {
    let exchange =
        source("src/application/provider_credential_enrollment/broker/qualified_exchange.rs");
    let channel = exchange
        .split_once("pub(crate) trait QualifiedCredentialBrokerChannel")
        .and_then(|(_, rest)| rest.split_once("impl ProviderCredentialBroker"))
        .map(|(body, _)| body)
        .unwrap();
    assert!(channel.contains("_issue: QualifiedIssueTransmission"));
    assert!(channel.contains("fn send_qualified_prelude(&mut self)"));
    for forbidden in [
        "_receipt: &IssuedCredentialTicketAttempt",
        "_frame: CredentialBrokerFrame",
        "_context_sha256: [u8; 32]",
        "_ticket_sha256: [u8; 32]",
        "_bundle: Vec<u8>",
    ] {
        assert!(
            !channel.contains(forbidden),
            "loose channel authority: {forbidden}"
        );
    }
    assert_eq!(
        exchange.matches("QualifiedIssueTransmission::new(").count(),
        1
    );
    assert!(!exchange.contains("into_qualified_signing_material"));
    let fence =
        source("src/protected_activation/control_v3/initial_exchange/qualification_fence.rs");
    assert_eq!(
        fence
            .matches("FencedWriterExchange::from_postcommit(")
            .count(),
        1
    );
    assert!(fence.contains("Result<FencedWriterExchange, Error>"));
    assert!(!fence.contains("Result<(QualifiedIssuedTicket, WriterAdmissionBundle), Error>"));
    for forbidden in [
        "fn context_sha256(&self)",
        "fn ticket_sha256(&self)",
        "fn into_bytes(self)",
    ] {
        assert!(
            !fence.contains(forbidden),
            "bundle extractor remains: {forbidden}"
        );
    }

    let issue = source("src/application/provider_credential_enrollment/broker/issue.rs");
    assert!(!issue.contains("pub(crate) fn issue_frame_for_receipt"));
    assert!(!issue.contains("pub(super) fn issue_frame_for_receipt"));
    assert!(issue.contains("fn issue_frame_for_qualified("));
    assert_eq!(
        issue
            .matches("qualified.into_qualified_issue_members()")
            .count(),
        1
    );
    assert_eq!(
        exchange.matches(".into_qualified_frame_members()").count(),
        1
    );

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    assert_eq!(
        occurrences(&sources, "FencedWriterExchange::from_postcommit("),
        1
    );
    assert_eq!(occurrences(&sources, "QualifiedIssueTransmission::new("), 1);
    assert_eq!(occurrences(&sources, "into_signing_parts"), 3);
    assert_eq!(
        sites_with(&root, &sources, ".into_signing_parts()"),
        [
            PathBuf::from("application/provider_credential_enrollment/broker/unix.rs"),
            PathBuf::from(
                "application/provider_credential_enrollment/control_facade/protected_session/qualification/connected_test_support.rs"
            ),
        ]
    );
    for (needle, expected) in [
        (
            "into_qualified_signing_material",
            vec![
                "protected_activation/control_v3/initial_exchange/qualification_fence.rs",
                "application/provider_credential_enrollment/broker/unix.rs",
                "application/provider_credential_enrollment/control_facade/protected_session/qualification/connected_test_support.rs",
            ],
        ),
        (
            "into_qualified_issue_members",
            vec![
                "application/provider_credential_enrollment/broker/issue.rs",
                "application/provider_credential_enrollment/broker/qualified_exchange.rs",
            ],
        ),
        (
            "into_qualified_frame_members",
            vec![
                "application/provider_credential_enrollment/broker/issue.rs",
                "application/provider_credential_enrollment/broker/qualified_exchange.rs",
            ],
        ),
    ] {
        let mut expected = expected.into_iter().map(PathBuf::from).collect::<Vec<_>>();
        expected.sort();
        assert_eq!(sites_with(&root, &sources, needle), expected);
        let expected_occurrences = if needle == "into_qualified_signing_material" {
            3
        } else {
            2
        };
        assert_eq!(
            occurrences(&sources, needle),
            expected_occurrences,
            "unexpected {needle} use"
        );
    }
}
