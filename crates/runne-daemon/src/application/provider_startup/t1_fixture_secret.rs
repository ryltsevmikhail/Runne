use runne_security::SecretBroker;
use sha2::{Digest as _, Sha256};

#[cfg(not(test))]
const SELECTOR: &str = "RUNNE_TEST_T1_TRUST_COMPOSITION";
const FAKE_ENV_DIGESTS: [(&str, &str, &str); 2] = [
    (
        "FAKE-SECRET-003",
        "033e851dc79fc831e5a08ffb7bc689f921712f5a99bc9848a424eab395a86eaf",
        "RUNNE_T1_FAKE_SECRET_ENV",
    ),
    (
        "FAKE-SECRET-006",
        "e37597ed8008f1ed14e8359f41a259e9311f34090362de273c43f0b8cc9c7a5e",
        "RUNNE_T1_FAKE_CRASH_REPORT_VAR",
    ),
];
const FROZEN_SECRETS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/golden/t1/fake-canary-secrets-v1.json"
));

/// Registers exactly the synthetic S7 canary in the isolated Linux T1 process.
/// No secret environment value is read; the frozen fixture is the only source.
#[cfg(not(test))]
pub(super) fn register_if_selected(broker: &mut SecretBroker) -> Result<(), ()> {
    register_for_selector(broker, std::env::var_os(SELECTOR).as_deref())
}

fn register_for_selector(
    broker: &mut SecretBroker,
    selector: Option<&std::ffi::OsStr>,
) -> Result<(), ()> {
    if selector != Some(std::ffi::OsStr::new("1")) {
        return Ok(());
    }
    let fixture: serde_json::Value = serde_json::from_str(FROZEN_SECRETS).map_err(|_| ())?;
    for (id, expected_digest, expected_name) in FAKE_ENV_DIGESTS {
        let canary = fixture["canaries"]
            .as_array()
            .and_then(|canaries| canaries.iter().find(|item| item["id"] == id))
            .ok_or(())?;
        let value = canary["value"].as_str().ok_or(())?;
        if canary["env_name"].as_str() != Some(expected_name)
            || hex::encode(Sha256::digest(value.as_bytes())) != expected_digest
        {
            return Err(());
        }
        broker
            .register(expected_name, value.as_bytes().to_vec())
            .map_err(|_| ())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_application::prohibited_content::{
        CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
    };

    #[test]
    fn selector_requires_the_exact_fixture_value() {
        for value in [None, Some("true"), Some("01"), Some("0"), Some("")] {
            let selector = value.map(std::ffi::OsStr::new);
            let mut broker = SecretBroker::new();
            register_for_selector(&mut broker, selector).expect("disabled selector is safe");
            let guard = broker.prohibited_content_guard();
            for value in [
                b"RUNNE_T1_FAKE_ENV_VALUE_3c5d9e1a".as_slice(),
                b"RUNNE_T1_FAKE_CRASH_d901be37".as_slice(),
            ] {
                assert!(matches!(
                    guard.inspect(CanonicalContentBoundary::CanonicalMutation, value),
                    Ok(ContentDisposition::Allowed { .. })
                ));
            }
        }
        let mut broker = SecretBroker::new();
        register_for_selector(&mut broker, Some(std::ffi::OsStr::new("1")))
            .expect("exact test selector registers frozen canary");
        let guard = broker.prohibited_content_guard();
        for value in [
            b"RUNNE_T1_FAKE_ENV_VALUE_3c5d9e1a".as_slice(),
            b"RUNNE_T1_FAKE_CRASH_d901be37".as_slice(),
        ] {
            assert!(matches!(
                guard.inspect(CanonicalContentBoundary::CanonicalMutation, value),
                Ok(ContentDisposition::Prohibited { .. })
            ));
        }
    }
}
