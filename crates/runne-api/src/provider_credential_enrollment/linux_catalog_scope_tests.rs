use super::{
    tests::{facts, record},
    *,
};

#[test]
fn catalog_scope_covers_every_catalog_identity_without_broadening_v1() {
    let broad = LinuxEnrollmentActivationRecord {
        provider_scope: LinuxEnrollmentScope::Catalog,
        ..record()
    };
    let broad = LinuxEnrollmentActivationRecord::from_config_json(&broad.to_config_json()).unwrap();
    let legacy =
        LinuxEnrollmentActivationRecord::from_config_json(&record().to_config_json()).unwrap();
    for entry in crate::provider_catalog() {
        let provider =
            LinuxEnrollmentProvider::from_id(entry.provider_id).expect("closed identity");
        assert_eq!(
            evaluate_linux_enrollment(Some(&broad), &facts(), Some(provider)),
            LinuxEnrollmentDecision::Allowed,
            "{}",
            entry.provider_id
        );
        let expected = if entry.provider_id == "deepseek" {
            LinuxEnrollmentDecision::Allowed
        } else {
            LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::ProviderNotAllowed)
        };
        assert_eq!(
            evaluate_linux_enrollment(Some(&legacy), &facts(), Some(provider)),
            expected
        );
        assert_eq!(
            evaluate_linux_enrollment(None, &facts(), Some(provider)),
            LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::PolicyAbsent)
        );
        let copied = LinuxInstallationFacts {
            machine_id_digest: [99; 32],
            ..facts()
        };
        assert_eq!(
            evaluate_linux_enrollment(Some(&broad), &copied, Some(provider)),
            LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::InstallationMismatch)
        );
    }
}

#[test]
fn catalog_document_requires_exact_version_scope_and_approval() {
    let broad = LinuxEnrollmentActivationRecord {
        provider_scope: LinuxEnrollmentScope::Catalog,
        ..record()
    };
    let encoded = broad.to_config_json();
    assert_eq!(
        LinuxEnrollmentActivationRecord::from_config_json(&encoded),
        Some(broad)
    );
    for (key, value) in [
        (
            "schema",
            serde_json::json!("runne.linux-enrollment-activation.v1"),
        ),
        ("provider_scope", serde_json::json!("all")),
        ("provider_scope", serde_json::Value::Null),
        ("approval", serde_json::json!(TD1_APPROVAL_MARKER)),
    ] {
        let mut document: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        document[key] = value;
        assert!(LinuxEnrollmentActivationRecord::from_config_json(&document.to_string()).is_none());
    }
    let mut old: serde_json::Value = serde_json::from_str(&record().to_config_json()).unwrap();
    old["provider_scope"] = serde_json::json!("catalog");
    assert!(LinuxEnrollmentActivationRecord::from_config_json(&old.to_string()).is_none());
}
