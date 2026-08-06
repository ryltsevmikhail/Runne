use super::super::intent::{EnvironmentClassificationV1, ProcessEnvironmentGrantV1};
use super::super::{ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, ProcessContractError};

fn value(bytes: &[u8]) -> PortableUtf8V1 {
    PortableUtf8V1::from_bytes(bytes.to_vec()).unwrap()
}

#[test]
fn exact_grant_still_rejects_execution_shaping_environment_names() {
    let bounds = InputBoundsV1::new(2, 16, 32).unwrap();
    assert_eq!(
        ProcessEnvironmentGrantV1::exact(
            vec![(
                value(b"LD_PRELOAD"),
                value(b"/safe/lib.so"),
                EnvironmentClassificationV1::NonSecret,
            )],
            bounds,
        ),
        Err(ProcessContractError::EnvironmentDenied)
    );
}

#[test]
fn exact_grant_rejects_search_path_environment_names() {
    let bounds = InputBoundsV1::new(3, 20, 48).unwrap();
    for name in [
        ["PA", "TH"].concat(),
        ["DYLD_LIBRARY_", "PA", "TH"].concat(),
        ["PYTHON", "PA", "TH"].concat(),
    ] {
        assert_eq!(
            ProcessEnvironmentGrantV1::exact(
                vec![(
                    value(name.as_bytes()),
                    value(b"safe"),
                    EnvironmentClassificationV1::NonSecret,
                )],
                bounds,
            ),
            Err(ProcessContractError::EnvironmentDenied)
        );
    }
}

#[test]
fn exact_grant_rejects_all_dynamic_loader_environment_names() {
    let bounds = InputBoundsV1::new(12, 40, 80).unwrap();
    for name in [
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "GCONV_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
    ] {
        assert_eq!(
            ProcessEnvironmentGrantV1::exact(
                vec![(
                    value(name.as_bytes()),
                    value(b"safe"),
                    EnvironmentClassificationV1::NonSecret,
                )],
                bounds,
            ),
            Err(ProcessContractError::EnvironmentDenied),
            "must deny {name}"
        );
    }
}

#[test]
fn exact_grant_allows_benign_canonical_environment_name() {
    let bounds = InputBoundsV1::new(2, 16, 32).unwrap();
    let grant = ProcessEnvironmentGrantV1::exact(
        vec![(
            value(b"LANG"),
            value(b"C"),
            EnvironmentClassificationV1::NonSecret,
        )],
        bounds,
    )
    .unwrap();
    let environment = ExplicitEnvironmentV1::from_exact_grant(
        &grant,
        vec![(value(b"LANG"), value(b"C"))],
        bounds,
    )
    .unwrap();
    assert!(!environment.is_empty());
}

#[test]
fn exact_environment_rejects_noncanonical_duplicate_and_bounded_entries() {
    let bounds = InputBoundsV1::new(2, 3, 6).unwrap();
    assert_eq!(
        ProcessEnvironmentGrantV1::exact(
            vec![(
                value(b"bad"),
                value(b"ok"),
                EnvironmentClassificationV1::NonSecret
            )],
            bounds,
        ),
        Err(ProcessContractError::IntentMalformed)
    );
    assert_eq!(
        ProcessEnvironmentGrantV1::exact(
            vec![
                (
                    value(b"KEY"),
                    value(b"ok"),
                    EnvironmentClassificationV1::NonSecret
                ),
                (
                    value(b"KEY"),
                    value(b"ok"),
                    EnvironmentClassificationV1::NonSecret
                ),
            ],
            InputBoundsV1::new(2, 8, 16).unwrap(),
        ),
        Err(ProcessContractError::IntentMalformed)
    );
    assert_eq!(
        ProcessEnvironmentGrantV1::exact(
            vec![(
                value(b"KEY"),
                value(b"value"),
                EnvironmentClassificationV1::NonSecret
            )],
            bounds,
        ),
        Err(ProcessContractError::InputBoundsExceeded)
    );
}
