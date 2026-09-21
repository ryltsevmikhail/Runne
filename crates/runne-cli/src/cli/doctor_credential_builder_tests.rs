// Hermetic tests for the single-probe credential check builder (slice A).
//
// `credential_check_from_probe` builds the doctor credential check from one
// already-taken `CredentialProbe` value: the production call site probes the
// store exactly once and derives both the message and its stable id from
// that single observation. Every probe here is a synthetic enum literal —
// no native store, no network, no host state.

use super::*;

const PROVIDERS: [&str; 2] = ["openai", "deepseek"];

const ALL_PROBES: [CredentialProbe; 6] = [
    CredentialProbe::Configured,
    CredentialProbe::Missing,
    CredentialProbe::Unsupported,
    CredentialProbe::AccessDenied,
    CredentialProbe::IdentityMismatch,
    CredentialProbe::Unavailable,
];

fn tier(probe: CredentialProbe, active: bool) -> CheckStatus {
    match (probe, active) {
        (CredentialProbe::Configured, _) => CheckStatus::Ok,
        (
            CredentialProbe::Missing,
            true,
        )
        | (CredentialProbe::AccessDenied | CredentialProbe::IdentityMismatch, _) => {
            CheckStatus::Error
        }
        (
            CredentialProbe::Missing,
            false,
        )
        | (CredentialProbe::Unsupported | CredentialProbe::Unavailable, _) => CheckStatus::Warning,
    }
}

#[test]
fn builder_maps_every_probe_variant_to_its_status_tier() {
    for provider in PROVIDERS {
        let name = format!("Credential ({provider})");
        for active in [true, false] {
            for probe in ALL_PROBES {
                let check = credential_check_from_probe(probe, provider, active);
                assert_eq!(check.status, tier(probe, active), "{probe:?} active={active}");
                assert_eq!(check.name, name);
                let details = check.details.as_deref().expect("details always present");
                assert!(details.contains("Source: "), "details carry the source: {details}");
                assert!(!details.contains("sk-"), "no token material: {details}");
            }
        }
    }
}

#[test]
fn messages_name_the_provider_and_end_with_the_stable_id() {
    let cases = [
        (CredentialProbe::Configured, false, "openai credential configured"),
        (
            CredentialProbe::Missing,
            true,
            "openai credential missing (active provider)",
        ),
        (CredentialProbe::Missing, false, "openai credential not configured"),
        (
            CredentialProbe::AccessDenied,
            true,
            "openai credential access denied",
        ),
        (
            CredentialProbe::IdentityMismatch,
            false,
            "openai credential identity mismatch",
        ),
        (
            CredentialProbe::Unavailable,
            true,
            "cannot check openai credential status",
        ),
    ];
    for (probe, active, prefix) in cases {
        let check = with_check_id(
            credential_check_from_probe(probe, "openai", active),
            credential_check_id(probe, active),
        );
        assert!(check.message.starts_with(prefix), "{}", check.message);
        let suffix = format!(" [{}]", credential_check_id(probe, active));
        assert!(check.message.ends_with(&suffix), "{}", check.message);
    }
    // The unsupported-backend message is a platform fact, not per-provider.
    let check = with_check_id(
        credential_check_from_probe(CredentialProbe::Unsupported, "deepseek", false),
        credential_check_id(CredentialProbe::Unsupported, false),
    );
    assert_eq!(
        check.message,
        "credential storage not supported on this platform [credential.unsupported]"
    );
}

#[test]
fn enrollment_guidance_appears_only_for_missing_and_denied() {
    for probe in [CredentialProbe::Missing, CredentialProbe::AccessDenied] {
        let check = credential_check_from_probe(probe, "deepseek", true);
        let details = check.details.as_deref().expect("details");
        assert!(details.contains("provider-credential broker"), "{details}");
    }
    for probe in [
        CredentialProbe::Configured,
        CredentialProbe::Unsupported,
        CredentialProbe::IdentityMismatch,
        CredentialProbe::Unavailable,
    ] {
        let check = credential_check_from_probe(probe, "deepseek", false);
        let details = check.details.as_deref().expect("details");
        assert!(!details.contains("broker"), "{details}");
    }
}

#[test]
fn builder_is_a_pure_function_of_the_single_probe_value() {
    for probe in ALL_PROBES {
        for active in [true, false] {
            let first = credential_check_from_probe(probe, "openai", active);
            let second = credential_check_from_probe(probe, "openai", active);
            assert_eq!(first.status, second.status);
            assert_eq!(first.message, second.message);
            assert_eq!(first.details, second.details);
        }
    }
}
