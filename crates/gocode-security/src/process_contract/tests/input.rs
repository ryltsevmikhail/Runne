use super::super::{BoundedArgvV1, InputBoundsV1, PortableUtf8V1, ProcessContractError};

fn value(bytes: &[u8]) -> PortableUtf8V1 {
    PortableUtf8V1::from_bytes(bytes.to_vec()).unwrap()
}

#[test]
fn argv_enforces_count_element_and_total_bounds() {
    let bounds = InputBoundsV1::new(1, 3, 3).unwrap();
    assert_eq!(
        BoundedArgvV1::new(vec![value(b"one"), value(b"two")], bounds),
        Err(ProcessContractError::InputBoundsExceeded)
    );
    assert_eq!(
        BoundedArgvV1::new(vec![value(b"four")], bounds),
        Err(ProcessContractError::InputBoundsExceeded)
    );
    assert_eq!(
        BoundedArgvV1::new(
            vec![value(b"one"), value(b"two")],
            InputBoundsV1::new(2, 3, 5).unwrap()
        ),
        Err(ProcessContractError::InputBoundsExceeded)
    );
}

#[test]
fn portable_utf8_rejects_invalid_utf8_and_nul() {
    assert_eq!(
        PortableUtf8V1::from_bytes(vec![0xff]),
        Err(ProcessContractError::IntentMalformed)
    );
    assert_eq!(
        PortableUtf8V1::from_bytes(b"a\0b".to_vec()),
        Err(ProcessContractError::IntentMalformed)
    );
}

#[test]
fn shell_like_argv_is_preserved_as_literal_portable_utf8() {
    let argv = BoundedArgvV1::new(
        vec![value(b";|$(whoami)`id`")],
        InputBoundsV1::new(1, 32, 32).unwrap(),
    )
    .unwrap();
    assert_eq!(argv.values()[0].bytes(), b";|$(whoami)`id`");
}
