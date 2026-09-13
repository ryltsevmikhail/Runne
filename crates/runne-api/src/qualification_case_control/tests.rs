use crate::{ProviderCredentialProviderV1, RunBinding};

use super::{
    MAX_QUALIFICATION_CASE_CONTROL_BYTES, QUALIFICATION_CASE_SELECTORS, QualificationCaseAction,
    QualificationCaseControlReply, QualificationCaseControlRequest, QualificationCaseSelector,
};

fn binding() -> RunBinding {
    RunBinding::new(
        "qualification-run-1",
        [1; 20],
        [2; 32],
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
    )
    .expect("binding")
}

fn request(
    action: QualificationCaseAction,
    revision: Option<u64>,
) -> QualificationCaseControlRequest {
    QualificationCaseControlRequest::new(
        binding(),
        [7; 32],
        [8; 32],
        1,
        QualificationCaseSelector::parse("pair_create_readback").expect("selector"),
        ProviderCredentialProviderV1::DeepSeek,
        action,
        revision,
        100,
    )
    .expect("request")
}

#[test]
fn exact_inventory_is_sorted_and_parses_only_its_54_selectors() {
    assert_eq!(QUALIFICATION_CASE_SELECTORS.len(), 54);
    assert!(
        QUALIFICATION_CASE_SELECTORS
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    for selector in QUALIFICATION_CASE_SELECTORS {
        assert_eq!(
            QualificationCaseSelector::parse(selector).unwrap().as_str(),
            selector
        );
    }
    assert!(QualificationCaseSelector::parse("pair_create_readback_v2").is_err());
}

#[test]
fn pair_create_may_omit_revision_but_every_other_action_requires_one() {
    assert!(
        QualificationCaseControlRequest::new(
            binding(),
            [7; 32],
            [8; 32],
            1,
            QualificationCaseSelector::parse("pair_create_readback").unwrap(),
            ProviderCredentialProviderV1::OpenAi,
            QualificationCaseAction::Pair,
            None,
            100,
        )
        .is_ok()
    );
    for action in [
        QualificationCaseAction::Readback,
        QualificationCaseAction::Rotate,
        QualificationCaseAction::Revoke,
        QualificationCaseAction::VerifyLocal,
        QualificationCaseAction::VerifyRemote,
    ] {
        assert!(
            QualificationCaseControlRequest::new(
                binding(),
                [7; 32],
                [8; 32],
                1,
                QualificationCaseSelector::parse("rotation").unwrap(),
                ProviderCredentialProviderV1::OpenAi,
                action,
                None,
                100,
            )
            .is_err()
        );
    }
    assert!(
        QualificationCaseControlRequest::new(
            binding(),
            [7; 32],
            [8; 32],
            0,
            QualificationCaseSelector::parse("rotation").unwrap(),
            ProviderCredentialProviderV1::OpenAi,
            QualificationCaseAction::Rotate,
            Some(0),
            100,
        )
        .is_err()
    );
    assert!(
        QualificationCaseControlRequest::new(
            binding(),
            [7; 32],
            [8; 32],
            1,
            QualificationCaseSelector::parse("pair_create_readback").unwrap(),
            ProviderCredentialProviderV1::OpenAi,
            QualificationCaseAction::Pair,
            Some(0),
            100,
        )
        .is_err()
    );
    assert!(QualificationCaseAction::parse("delete").is_err());
}

#[test]
fn request_rejects_zero_run_session_fields() {
    for (challenge, session, sequence) in [
        ([0; 32], [8; 32], 1),
        ([7; 32], [0; 32], 1),
        ([7; 32], [8; 32], 0),
    ] {
        assert!(
            QualificationCaseControlRequest::new(
                binding(),
                challenge,
                session,
                sequence,
                QualificationCaseSelector::parse("pair_create_readback").unwrap(),
                ProviderCredentialProviderV1::DeepSeek,
                QualificationCaseAction::Pair,
                None,
                100,
            )
            .is_err()
        );
    }
}

#[test]
fn canonical_request_round_trip_rejects_unknown_duplicate_trailing_and_noncanonical_bytes() {
    let request = request(QualificationCaseAction::Pair, Some(9));
    let encoded = request.encode().expect("encode");
    let decoded = QualificationCaseControlRequest::decode(&encoded).expect("decode");
    assert_eq!(decoded.encode().unwrap(), encoded);
    assert_eq!(decoded.binding().manifest_sha256(), [5; 32]);

    let text = String::from_utf8(encoded.clone()).expect("wire utf8");
    let duplicate = text.replacen(
        "\"kind\":\"case_request\",",
        "\"kind\":\"case_request\",\"kind\":\"case_request\",",
        1,
    );
    assert!(QualificationCaseControlRequest::decode(duplicate.as_bytes()).is_err());
    assert!(QualificationCaseControlRequest::decode(format!(" {text}").as_bytes()).is_err());
    let unknown = text.replacen('}', ",\"unknown\":true}", 1);
    assert!(QualificationCaseControlRequest::decode(unknown.as_bytes()).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(QualificationCaseControlRequest::decode(&trailing).is_err());
    assert!(
        QualificationCaseControlRequest::decode(&vec![
            b'x';
            MAX_QUALIFICATION_CASE_CONTROL_BYTES + 1
        ])
        .is_err()
    );
}

#[test]
fn reply_echoes_every_request_field_and_is_bounded_by_run_lifetime() {
    let reply =
        QualificationCaseControlReply::new(request(QualificationCaseAction::Rotate, Some(7)), 99)
            .expect("reply");
    let encoded = reply.encode().expect("encode");
    let decoded = QualificationCaseControlReply::decode(&encoded).expect("decode");
    let decoded_request = decoded.request();
    assert_eq!(
        decoded_request.binding().workflow_run_id(),
        "qualification-run-1"
    );
    assert_eq!(decoded_request.binding().source_revision(), [1; 20]);
    assert_eq!(decoded_request.binding().candidate_sha256(), [2; 32]);
    assert_eq!(decoded_request.binding().raw_v3_tuple_sha256(), [3; 32]);
    assert_eq!(decoded_request.binding().namespace_sha256(), [4; 32]);
    assert_eq!(decoded_request.binding().manifest_sha256(), [5; 32]);
    assert_eq!(decoded_request.binding().profile_sha256(), [6; 32]);
    assert_eq!(decoded_request.daemon_challenge(), [7; 32]);
    assert_eq!(decoded_request.session_id(), [8; 32]);
    assert_eq!(decoded_request.sequence(), 1);
    assert_eq!(decoded_request.selector().as_str(), "pair_create_readback");
    assert_eq!(
        decoded_request.provider(),
        ProviderCredentialProviderV1::DeepSeek
    );
    assert_eq!(decoded_request.action(), QualificationCaseAction::Rotate);
    assert_eq!(decoded_request.expected_credential_revision(), Some(7));
    assert_eq!(decoded_request.run_not_after(), 100);
    assert_eq!(decoded.expires_at(), 99);
    assert!(
        QualificationCaseControlReply::new(request(QualificationCaseAction::Pair, None), 101)
            .is_err()
    );
    let wrong_domain = String::from_utf8(encoded).expect("wire utf8").replacen(
        "runne/qualification-case-control/v1",
        "runne/qualification-case-control/v2",
        1,
    );
    assert!(QualificationCaseControlReply::decode(wrong_domain.as_bytes()).is_err());
}
